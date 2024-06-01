function displayLoading() {
    document.getElementById("loading").style.display = "block";
    
}
function dontdisplayLoading(){
    document.getElementById("transcript").style.display = "none";
}
function displayTranscript(message) {
    document.getElementById("loading").style.display = "none";
    document.getElementById("transcript").style.display = "block";
    document.getElementById("transcript").style.whiteSpace = "pre-line";  // Preserve line breaks
    document.getElementById("transcript").innerHTML = message;
}

function processUrl() {
    const youtubeUrl = document.getElementById("youtube_url").value;
    displayLoading();
    //document.getElementById("question").disabled = false;

    fetch('/process_url', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `youtube_url=${encodeURIComponent(youtubeUrl)}`,
    })
    .then(response => response.json())
    .then(result => {
        displayTranscript("Ask your question");
        if (!result.transcript) {
            document.getElementById("question").disabled = false;
        }
    })
    .catch(error => {
        console.error('Error:', error);
        displayTranscript("An error occurred during processing.");

        document.getElementById("question").disabled = false;
    });
}
function askQuestion() {
    const question = document.getElementById("question").value;
    displayLoading();
    document.getElementById("question").disabled = true;
    const youtubeUrl = document.getElementById("youtube_url").value;
    const targetLanguage = document.getElementById("other_language_textbox").value;
    if ((!targetLanguage) || (!other_language_textbox)) {
        alert("Please select a target language.");
        return;
    }

    fetch('/ask_question', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `question=${encodeURIComponent(question)}&target_language=${encodeURIComponent(targetLanguage)}`,
    })
    .then(response => response.json())
    .then(result => {
        if (result.transcript) 
        {
            console.log(result.transcript);
            const transcriptText = result.transcript
            .map(line => {
                const match = line.match(/(\d{2}:\d{2} - )(.+)/);
                if (match) {
                    const timestamp = match[1];
                    const text = match[2];
                    return `${timestamp}${text}`;
                } 
                else {
                    return ''; // or some default value
                }
            })
            .join('\n');
            displayTranscript(transcriptText);
            document.getElementById("email-section").style.display = "block";
            document.getElementById("email_subject").value = question; // Set subject
            //document.getElementById("email_content").value = "The Transcript for the video addressed by the url: "+youtubeUrl+"  is: \n\n"+transcriptText; // Set content
            document.getElementById("email_content").value = transcriptText; // Set content

        }
        else if (result.answer)
        {
            displayTranscript(`Answer: ${result.answer}`);
            document.getElementById("email-section").style.display = "block";
            document.getElementById("email_subject").value ="Question asked: "+ question; // Set subject
            // document.getElementById("email_content").value = "The Ai generated answer for the above question regarding the video addressed by the url: "+youtubeUrl+"  is: \n\n"+result.answer; // Set content
            document.getElementById("email_content").value = result.answer; // Set content

        }
        else {
            displayTranscript("NO TRANSCRIPT / VIDEO LANGUAGE MISMATCH :( ");
        }
    })
    .catch(error => {
        console.error('Error:', error);
        displayTranscript("An error occurred during processing.");
    })
    .finally(() => {
        document.getElementById("question").disabled = false;
    });
}

/*function sendEmail() {
    const toEmailElements = document.querySelectorAll(".to-email");
    const subject = document.getElementById("email_subject").value;
    const content = document.getElementById("email_content").value;
    const targetLanguage = document.getElementById("target_language").value;

    let invalidEmail = false;

    toEmailElements.forEach((toEmailElement) => {
        const toEmail = toEmailElement.value;
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        if (!emailRegex.test(toEmail)) {
            alert("Invalid email address: " + toEmail);
            invalidEmail = true;
        }
    });

    if (invalidEmail) {
        return;
    }

    document.getElementById("loading").style.display = "block";
    document.getElementById("transcript").style.display = "none";

    // Create an array of email addresses
    const toEmails = Array.from(toEmailElements).map((toEmailElement) =>
        encodeURIComponent(toEmailElement.value)
    );

    fetch('/send_email', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `to_emails=${toEmails.join(',')}&subject=${encodeURIComponent(subject)}&content=${encodeURIComponent(content)}`,
    })
    .then(response => response.json())
    .then(result => {
        if (result.error) {
            console.error('Error sending email:', result.error);
            alert('An error occurred while sending the email.');
        } else {
            console.log(result.status);  // Log the status for debugging
            alert(result.status);
        }
    })
    .catch(error => {
        console.error('Error sending email:', error);
        alert('An error occurred while sending the email.');
    })
    .finally(() => {
        document.getElementById("loading").style.display = "none";
        document.getElementById("transcript").style.display = "block";
    });
}*/
function getDescription() {
    const question = "A small, concise description of the video";
    const targetLanguage = document.getElementById("other_language_textbox").value;
    if (!targetLanguage) {
        alert("Please select a target language.");
        return null; // Return null if target language is not provided
    }

    return fetch('/ask_question', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `question=${encodeURIComponent(question)}&target_language=${encodeURIComponent(targetLanguage)}`,
    })
    .then(response => response.json())
    .then(result => {
        if (result.description) {
            // Return the description
            return result.description;
        } else {
            return null; // Return null if description is not available
        }
    })
    .catch(error => {
        console.error('Error:', error);
        return null; // Return null in case of an error
    });
}

function sendEmail() {
    const toEmailElements = document.querySelectorAll(".to-email");
    const question = document.getElementById("question").value;
    const subject = document.getElementById("email_subject").value;
    const answer = document.getElementById("email_content").value;
    const youtubeUrl = document.getElementById("youtube_url").value;
    const targetLanguage = document.getElementById("target_language").value;

    let invalidEmail = false;

    toEmailElements.forEach((toEmailElement) => {
        const toEmail = toEmailElement.value;
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

        if (!emailRegex.test(toEmail)) {
            alert("Invalid email address: " + toEmail);
            invalidEmail = true;
        }
    });

    if (invalidEmail) {
        return;
    }

    document.getElementById("loading").style.display = "block";
    document.getElementById("transcript").style.display = "none";
    const description ="sorry not available as of now"
    /*let description; // Declare the variable outside the block

    getDescription().then(returnedDescription => {
            if (returnedDescription !== null) {
                // Use the description
                //console.log(returnedDescription);
                // Assign it to your global variable
                description = returnedDescription;
            } else {
                console.log("No description available.");
            }
        });*/



    // Create an array of email addresses
    const toEmails = Array.from(toEmailElements).map((toEmailElement) =>
        encodeURIComponent(toEmailElement.value)
    );

    fetch('/send_email', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `to_emails=${toEmails.join(',')}&question=${encodeURIComponent(question)}&answer=${encodeURIComponent(answer)}&url=${encodeURIComponent(youtubeUrl)}&description=${encodeURIComponent(description)}`,
    })
    .then(response => response.json())
    .then(result => {
        if (result.error) {
            console.error('Error sending email:', result.error);
            alert('An error occurred while sending the email.');
        } else {
            console.log(result.status);  // Log the status for debugging
            alert(result.status);
        }
    })
    .catch(error => {
        console.error('Error sending email:', error);
        alert('An error occurred while sending the email.');
    })
    .finally(() => {
        document.getElementById("loading").style.display = "none";
        document.getElementById("transcript").style.display = "block";
    });
}


function handleLanguageSelection(select) {
    var helpLink = document.getElementById('help_link');
    var otherLanguageTextbox = document.getElementById('other_language_textbox');
    var inputValue = document.getElementById('question');
    if (select.value === 'other') 
    {
        helpLink.style.display = 'inline';
        otherLanguageTextbox.style.display = 'inline';
    } 
    else 
    {
        helpLink.style.display = 'none';
        otherLanguageTextbox.style.display = 'none';
    }
    otherLanguageTextbox.value = select.value;
}

function printTranscript() {
    const youtubeUrl = document.getElementById("youtube_url").value;

    fetch('/transcript_print', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/x-www-form-urlencoded',
        },
        body: `youtube_url=${encodeURIComponent(youtubeUrl)}`,
    })
    .then(response => response.json())
    .then(result => {
        console.log(result);

        if (result.transcript) {
            const transcriptText = result.transcript.map(line => {
                const match = line.match(/(\d{2}:\d{2} - )(.+)/);
                if (match) {
                    const timestamp = match[1];
                    const text = match[2];
                    return `${timestamp}${text}`;
                } 
                else {
                    return '';
                }
            }).join('\n');

            document.getElementById("email_subject").value = "Transcript";
            document.getElementById("email_content").value ="The Transcript for the video addressed by the url: "+youtubeUrl+"  is: \n\n"+ transcriptText;

            displayTranscript("The Transcript for the video addressed by above  url is: \n\n"+transcriptText);

            document.getElementById("email-section").style.display = "block";
        } 
        else 
        {
            console.error('No transcript available or empty transcript.');
            displayTranscript("No transcript available or empty transcript.");
        }
    })
    .catch(error => {
        console.error('Error:', error);
        displayTranscript("NO TRANSCRIPT / VIDEO LANGUAGE MISMATCH :( ");
    });
}
