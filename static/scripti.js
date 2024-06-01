function showHome() 
{
    document.getElementById("home").style.display = "block";
    document.getElementById("team").style.display = "none";
    document.getElementById("field").style.display = "none";
    
}
// function redirectToPage() 
// {
//     // Redirect to 'page.html'
//     window.location.href = '/page';
// }
// function take_to_main_page()
// {
//     window.location.href = 'page.html';
// }
function showTeam() 
{
    document.getElementById("home").style.display = "none";
    document.getElementById("team").style.display = "block";
    document.getElementById("field").style.display = "none";
    
}
function showField()
{
    document.getElementById("home").style.display = "none";
    document.getElementById("team").style.display = "none";
    document.getElementById("field").style.display = "block";
    

}
document.addEventListener("DOMContentLoaded", function() 
{
    // Smooth scrolling for menu links
    document.querySelectorAll('nav a').forEach(anchor => 
        {
        anchor.addEventListener('click', function (e) 
        {
            e.preventDefault();

            const targetId = this.getAttribute('href').substring(1);
            const targetElement = document.getElementById(targetId);

            window.scrollTo({
                top: targetElement.offsetTop - document.querySelector('nav').offsetHeight,
                behavior: 'smooth'
            });
        });
    });
});