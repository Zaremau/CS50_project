# Language HUB
#### Video Demo:  <https://www.youtube.com/watch?v=WOKR0csCSAI>
#### Description:
Language HUB is a a web application that is desinged to help language learners to keep track of their study time.
To make this application I have used flask, html with jinja syntax, javaScript and CSS. Along with language.db database.

There are four basic pages: profile, study session and statistics. In profile the user can enter all needen information about themselsves: first name, last name, main language, e-mail and password. In order to implement this page I have made three templates: profile, plofile-edited and security. In profile he user can change all of the information except password, because to do that the user needs to go through the link to the security template. At first I have created it as a seperate element in navagation bar, but later decided to move it to profile page. Profile-edited contains all of the information the user wrote in input. However, it doesn't take any information. I have written two functions to check weather the language and am e-mail the user is using are valid or not. After submitting the form, if the information is valid the user is redireced to profile-edited.

In order to implenemt study session I have created a template called study where the user can log the information about their study session. I made a timer using javaScript. After the countdown is over the information is submitted to the study_history table in a database.

To implenet statistics I have used Chart.js javascript library which uses the information about study logs from study_history. Id the user doesn't have any logged information statistics-sorry page will render. There are two charts. One of them is a pie chart that shows what was the focus of the user, what they have been studying the most. The line chart shows the amount of time the user has spent on studying in the last five days. There is also a function to change the overall data to specific language. It can be any language, not only the one that is choosen as main.

As for the homepage, I have decided that it will show if the user have been studying there main language(a.k.a their main study focus) as often as they should. If the user have not been studying enough, the page will show the messege to promt the user to study a bit more. The homepage also contains an inspirational quote that is randomly generated by an api. To make the page look better I have found a short video and added some css styles (styles are found online).

In order to provife security of password information I have use a hashing function.
All of the data is sored in language.db which has three tables: users, study_history, profiles.

Throughout the time I have spent on working on this project I have had to make decisions about the implementation of different parts. Wheather it is reasonable to add some of the functions to the server side or not. For example, first, to validate the user's input I have written a function on severver' side. However, at the end I have decded to move it to the user's side. Though, I have used one of the functions both on the server's and user's side. It turned out that to validate language input in study template I had to add the function in java script.