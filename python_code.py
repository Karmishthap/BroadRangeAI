import openai
from langchain.document_loaders import YoutubeLoader
# from langchain.indexes import VectorstoreIndexCreator
from youtube_transcript_api import YouTubeTranscriptApi
from urllib.parse import urlparse, parse_qs
from langdetect import detect
# from translate import Translator
# import re
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from googletrans import Translator as GoogleTranslator

def send_email(to_email, subject, content):
    from_email = 'botmyurl@gmail.com'
    smtp_server = 'smtp.gmail.com'
    smtp_port = 587
    smtp_username = 'botmyurl@gmail.com'
    smtp_password = 'zoki lhrj pncf dnuo'

    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject

    body = MIMEText(content)
    msg.attach(body)

    with smtplib.SMTP(smtp_server, smtp_port) as server:
        server.starttls()
        server.login(smtp_username, smtp_password)
        server.sendmail(from_email, to_email, msg.as_string())

    print("Email sent successfully!")

def send_login_email(to_email):
    subject = 'Login Email Verification'
    body = """ Your email has been verified for login. Thank you! """
    send_email(to_email, subject, body)

def send_signup_email(to_email):
    subject = 'Signup Email Verification'
    body = """ Your email has been verified for signup. Thank you! """
    send_email(to_email, subject, body)

# def send_forgotp_email(to_email):
#     subject = 'Forgot Password Email Verification'
#     body = """
#     <html>
#     <body>
#         <p>Your email has been verified for password recovery. Thank you!</p>
#     </body>
#     </html>
#     """
#     send_email(to_email, subject, body)
    
def get_function_by_signal(signal):
    functions = {
        'login': send_login_email,
        'signup': send_signup_email, 
        'email': send_email,
        # 'forgotp': send_forgotp_email,
    }
    return functions.get(signal)

def translate_text(text, target_language):
    try:
        translator = GoogleTranslator()
        translation = translator.translate(text, dest=target_language)
        return translation.text
    except Exception as e:
        print(f"Error during translation: {e}")
        return text

def extract_video_id(url):
    parsed_url = urlparse(url)

    if parsed_url.netloc == 'www.youtube.com' and parsed_url.path == '/watch':
        query_params = parse_qs(parsed_url.query)
        video_id = query_params.get('v', [None])[0]
        if video_id:
            return video_id

    if parsed_url.netloc == 'youtu.be':
        path_segments = parsed_url.path.split('/')
        if len(path_segments) > 1:
            return path_segments[1]

    return None

def get_transcript(video_id):
    try:
        transcript = YouTubeTranscriptApi.get_transcript(video_id)
        return transcript
    except KeyError as ke:
        print(f"KeyError in transcript: {ke}")
        return []
    except Exception as e:
        print(f"Error retrieving transcript: {e}")
        return []

def answer_question_with_transformers(transcript, question, target_language):
    print(f"Received question: {question}, target_language: {target_language}")
    question_language = detect(question)
    max_context_length = 8191
    truncated_transcript = ' '.join(entry['text'] for entry in transcript)
    truncated_transcript = truncated_transcript[:max_context_length - len(question)]

    if question_language != 'en':
        question = translate_text(question, 'en')

    print(f"Translated question: {question}, target_language: {target_language}")
    input_text = f"Video transcript: {truncated_transcript}. Question: {question}"

    try:
        openai.api_key = 'sk-proj-eYZ2B0iWpdyuy7hJmFZHT3BlbkFJb8ctSsbttn5yonMPo2ZI'
        response = openai.ChatCompletion.create(
            #model="gpt-4",
            model="gpt-3.5-turbo",
            messages=[
                {"role": "system", "content": "You are a helpful assistant."},
                {"role": "user", "content": input_text}
            ]
        )
        answer = response['choices'][0]['message']['content'].strip()
        if target_language != 'en':
            answer = translate_text(answer, target_language)

        print(f"Answer: {answer}")
        return answer

    except Exception as e:
        print(f"An error occurred during question-answering: {e}")
        return "Error during question-answering."

def main():
    try:
        youtube_url = input("Enter the YouTube URL: ")
        video_id = extract_video_id(youtube_url)

        if video_id is None:
            print("Invalid YouTube URL. Please provide a valid URL.")
            return

        transcript = get_transcript(video_id)

        while True:
            action = input("What would you like to do? ('transcript' to display transcript, 'q' to quit, or ask a question): ")

            if action.lower() == 'q':
                break
            elif action.lower() == 'transcript':
                for entry in transcript:
                    timestamp_seconds = entry['start']
                    timestamp_formatted = f"{int(timestamp_seconds // 60):02d}:{int(timestamp_seconds % 60):02d}"
                    text = entry['text']
                    formatted_entry = f"{timestamp_formatted}:  {text}"
                    print(formatted_entry)
            else:
                ai_answer = answer_question_with_transformers(transcript, action)
                print(f"Answer (using OpenAI): {ai_answer}")

    except Exception as e:
        print(f"An unexpected error occurred: {e}")

if __name__ == '__main__':
    main()