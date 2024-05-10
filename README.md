
# INCIDENT RESPONSE WITH WINDOWS
In a Security Operation Center (SOC), responding to incidents requires a structured approach. Rather than relying on individual improvisation, it's crucial to adhere to predetermined frameworks to ensure consistency and precision, especially in crisis situations. This section will delve into maintaining consistency in incident response protocols, an essential aspect for grasping the broader operational context.
<img width="779" alt="image" src="https://github.com/chromosems/Incident-Response-With-Windows/assets/44053943/655384ca-5f08-4f4c-8c9c-937480bcc3a9">


## Objective
When investigating a system that has been compromised or suspected of compromise, irrespective of its processing system, three pivotal questions must be addressed. The answers to these inquiries can significantly influence the trajectory and conclusion of the analysis.
- Could there be amalware currently active in the system
- Is there persistence of the attack
- Is there any suspicious internal or external communication?


### Skills Learned
- Analyzing malware in the operating system.
- Analyzing attack persistence.


### Tools Used
- Process Hacker to analyze active working process.
- Autoruns to determine attacker's persistence.

## Steps
-Analyzing Malware in Sytems
- The Process Hacker tool presents very detailed data regarding the processes in the system. Above, you can see the process relations, PID numbers, and the user information running in its most basic form. There are 3 critical points we must pay attention to while conducting a memory analysis:
Process Tree,Network Connections,Signature Status
-<img width="1260" alt="image" src="https://github.com/chromosems/Incident-Response-With-Windows/assets/44053943/9e259c92-c347-497e-a338-f35f7a9e8ed4">
- While dealing with process tree, its important to identify normal processes from anomalies,For example, it is normal to have a “brave.exe” named childprocess under the “chrome.exe” process because it may create different subprocesses for different tables
- <img width="240" alt="image" src="https://github.com/chromosems/Incident-Response-With-Windows/assets/44053943/eeeef656-9bc7-4b72-ace1-e121fdc551e7">
- Incase a “powershell.exe” process that has been created under the “chrome.exe” process? We cannot react normally to a PowerShell creation under a chrome process. We must suspect an exploitation situation and examine what the PowerShell has done and what commands it invited.We cannot expect a PowerShell to run under a web server process other than extraordinary circumstances.
- Another scanario here looking at the situation below, see that python.exe has been formed under cmd.exe. This situation may be legal but may also have run a malicious python command. In order to understand this, It must be double-clicked on “python.exe” and check which file/command was run within which parameters.
- <img width="203" alt="image" src="https://github.com/chromosems/Incident-Response-With-Windows/assets/44053943/5c0fdeba-6494-4a47-8d1b-3b9335995f2b">
-When  looking at the “command line” area,  see that the manage.py file was run within the parameters of “runserver” and in “current directory” notice where the procedure was conducted. We cannot definitely say that there is a suspicious situation here. In order to understand whether the situation is suspicious or malicious, we must analyze the “manage.py” file. As seen, this file is located at “C:\Users\gunal\Documents\Github\LetsDefend\letsdefend\
-<img width="425" alt="image" src="https://github.com/chromosems/Incident-Response-With-Windows/assets/44053943/5c84f1a8-c259-47d6-a606-d9fc243d6811">

- ASSESSING ATTACK PERSISTENCE
  
-A method that is commonly used by attackers to maintain persistence is to create users. In fact, maintaining persistence is not the only reason why this is conducted. We observe that when attacker(s) take control of the “Administrator” account, they create new users. Because this is an important user, and its activity may be regularly tracked. Thus, they create a new user that will not attract a lot of attention and, if possible, they increase that user’s privileges.The users that are created usually include keywords like “support”, “sysadmin”, “admin”. In most companies, users with names like these will not attract much attention.During an incident response procedure, there are 2 things that we must quickly evaluate.Is there currently a user in the system that should not be there?Has a user been created during the attack and deleted after that?

-To list the currently active users in the system, we can use the “net user” command via cmd
- <img width="666" alt="image" src="https://github.com/chromosems/Incident-Response-With-Windows/assets/44053943/8d0909a4-2c30-4449-b53b-3a9c5a8c16e8">
-As a result, if there is a user that should not be there and we need more detailed information regarding this specific user, we can conduct a search my typing “net user USERNAME”.
- <img width="517" alt="image" src="https://github.com/chromosems/Incident-Response-With-Windows/assets/44053943/ebfd4d15-c4ce-42c8-b274-2cacdfdd220e">
- In this example, if the “Last logon” and “Password last set” values are paired with the time of the attack, we can approach the situation with suspicion.




