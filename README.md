## Lab 4
### Class: CS 116
### Author Gabe Smithline

### Implementation:
- I believe my handing of the input was correct as that was taken directly from the example
- I believe my functionality for running the checks for FIN Scan, XMAS Scan, Null Scan, and Nikto Scan are correct
- The SMB scan took some research on my part to find which port it would be on, It seemed to work in the tests I ran although I am not 100% sure
- I found I needed to also add scanning for port 139 as well as specify scapy to sniff on port 139 and 445.  Looking at the code in scapy I see sport is specified as a random int unless given an input integer. 
- The functionality to decode the encoded information in pcaps: set1, set2, and set3 works
- I did run into some trouble, I know HTTP would be on port 80 so I wanted to add an if statement to check for that but it seemed to not work
- I ended up just directly checking for the Authorization Basic string as I remember running that search in wireshark
- Found utilizing specific ports was the most efficient way and searching for specific strings to find the encoded information of interest was most efficient.

### Resources/Help:
- I did not get any help for anyone in this class 
- I used the following resources:
    - [Scapy Documentation](https://buildmedia.readthedocs.org/media/pdf/scapy/stable/scapy.pdf)
    - [NMAP Documentation](https://nmap.org/docs.html)
    - [SMB](https://www.upguard.com/blog/smb-port#:~:text=SMB%20is%20a%20network%20file,dialects%20that%20communicate%20over%20NetBIOS.)
    - [OSI Model](https://www.imperva.com/learn/application-security/osi-model/)
    - [Section 3 Slides](https://canvas.tufts.edu/courses/40248/pages/3-dot-2-reading?module_item_id=827092)
    - [FTP vs. SFTP](https://titanftp.com/2021/02/23/whats-the-difference-ftp-sftp-and-ftp-s/#:~:text=The%20FTP%20protocol%20typically%20uses,Control%20Connection%20or%20Command%20Connection.)
    - [Nikto Information](https://www.freecodecamp.org/news/an-introduction-to-web-server-scanning-with-nikto/)
    - [HTTP vs. HTTPS]( https://www.cloudflare.com/learning/ssl/why-is-http-not-secure/#:~:text=HTTPS%20is%20HTTP%20with%20encryption,far%20more%20secure%20than%20HTTP.)
    - [Youtube Video](https://www.youtube.com/watch?v=gOcT5r0spVM)
    - [sport use](https://stackoverflow.com/questions/41734149/comparing-port-numbers-of-packets-in-python)
    - [SMB Port Research](https://4sysops.com/archives/smb-port-number-ports-445-139-138-and-137-explained/) 

   
### Time spent:
- I spent 3-4ish hours on this, mostly spent reading documentation

## Questions:
- Are the heuristics used in this assignment to determine incidents "even that good"?
    - I think its ok for this is assignment but not in the real world.  For a lot of the the decoding I'm relying on the fact that that the strings contain the substrings: "USER", "LOGIN", or "AUTHORIZATION BASIC"; I could easily imagine situation where one could possibly get around this.  One other aspect I was wondering about was the chance of false positives.  

- If you have spare time in the future, what would you add to the program or do differently with regards to detecting incidents?
    - I think I would also track spoofing and cross site scripting.  I noticed that one can track ARP with the scapy library so I think I would add some logic that after X amount of ARP detections I'd give some notice of possible ARP spoofing.  I also noticed one can track the cross site scripting with the Nikto scan. I think I would add an extra alert when that is detected.  I'd also find some way to prioritize scans, maybe make it configurable based off of what the user is looking for.  It can be hard to find what you are looking for when a lot of input is coming in. I also did not print out the load, I only printed the load when unencryptoed authentication information was detected as in class it was mentioned we just needed to print the load when we detected the unencrypted information. 

    

