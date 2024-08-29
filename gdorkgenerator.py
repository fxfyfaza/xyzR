def generate_dorks(domain):
    dorks = {
        "PHP extension w/ parameters": f"site:{domain} ext:php inurl:? ",
        "API Endpoints": f"site:{domain} inurl:api | site:{domain} /rest | site:{domain} /v1 | site:{domain} /v2 | site:{domain} /v3",
        "Juicy Extensions": f"site:{domain} ext:log | ext:txt | ext:conf | ext:cnf | ext:env | ext:bak | ext:swp | ext:old | ext:~ | ext:git | ext:svn | ext:htpasswd | ext:htaccess | ext:json",
        "High G inurl keywords": f"inurl:conf | inurl:env | inurl:cgi | inurl:bin | inurl:etc | inurl:root | inurl:admin | inurl:php site:{domain}",
        "Server Errors": f'inurl:"error" | intitle:"exception" | intitle:"failure" | intitle:"server at" | inurl:exception | "database error" | "SQL syntax" | "undefined index" | "unhandled exception" | "stack trace" site:{domain}',
        "XSS prone parameters": f'inurl:q= | inurl:s= | inurl:search= | inurl:query= | inurl:keyword= | inurl:lang= inurl:& site:{domain}',
        "Open Redirect prone parameters": f'inurl:url= | inurl:return= | inurl:next= | inurl:redirect= | inurl:redir= | inurl:r2= | inurl:r3= inurl:& site:{domain}',
        "SQLi Prone Parameters": f'inurl:id= | inurl:pid= | inurl:category= | inurl:cat= | inurl:action= | inurl:sid= | inurl:dir= inurl:& site:{domain}',
        "SSRF Prone Parameters": f'inurl:http | inurl:url= | inurl:path= | inurl:dest= | inurl:html= | inurl:domain= | inurl:page= inurl:& site:{domain}',
        "LFI Prone Parameters": f'inurl:include= | inurl:dir= | inurl:detail= | inurl:folder= | inurl:inc= | inurl:locate= | inurl:doc= | inurl:conf= inurl:& site:{domain}',
        "RCE Prone Parameters": f'inurl:cmd= | inurl:exec= | inurl:query= | inurl:keyword= | inurl:lang= | inurl:run= | inurl:ping= inurl:& site:{domain}',
        "FILE Upload endpoints": f'site:{domain} "choose file"',
        "API Docs": f'inurl:apidocs | inurl:api-docs | inurl:swagger | inurl:api-explorer site:{domain}',
        "Login Pages": f'inurl:login | inurl:signin | intitle:login | intitle:signin | inurl:secure site:{domain}',
        "Test Environments": f'inurl:test | inurl:env | inurl:dev | inurl:staging | inurl:sandbox | inurl:debug | inurl:temp | inurl:internal | inurl:demo site:{domain}',
        "Sensitive Documents": f'site:{domain} ext:txt | ext:pdf | ext:xml | ext:xls | ext:xlsx | ext:ppt | ext:pptx | ext:doc | ext:docx intext:“confidential” | intext:“Not for Public Release” | intext:”internal use only” | intext:“do not distribute”',
        "Sensitive Parameters": f'inurl:email= | inurl:phone= | inurl:password= | inurl:secret= inurl:& site:{domain}',
        "Adobe Experience Manager": f'inurl:/content/usergenerated | inurl:/content/dam | inurl:/jcr:content | inurl:/libs/granite | inurl:/etc/clientlibs | inurl:/content/geometrixx | inurl:/bin/wcm | inurl:/crx/de site:{domain}',
        "Disclosed XSS and Open Redirects": f'site:openbugbounty.org inurl:reports intext:{domain}',
        "Google Groups": f'site:groups.google.com "{domain}"',
        "Code Leaks": f'site:pastebin.com "{domain}" | site:jsfiddle.net "{domain}" | site:codebeautify.org "{domain}" | site:codepen.io "{domain}"',
        "Cloud Storage": f'site:s3.amazonaws.com "{domain}" | site:blob.core.windows.net "{domain}" | site:googleapis.com "{domain}" | site:drive.google.com "{domain}" | site:dev.azure.com "{domain}" | site:onedrive.live.com "{domain}" | site:digitaloceanspaces.com "{domain}" | site:sharepoint.com "{domain}" | site:s3-external-1.amazonaws.com "{domain}" | site:s3.dualstack.us-east-1.amazonaws.com "{domain}" | site:dropbox.com/s "{domain}" | site:box.com/s "{domain}" | site:docs.google.com inurl:"/d/" "{domain}"',
        "JFrog Artifactory": f'site:jfrog.io "{domain}"',
        "Firebase": f'site:firebaseio.com "{domain}" | site:*/security.txt "bounty"',
    }

    return dorks

def display_dorks(dorks):
    for category, query in dorks.items():
        print(f"{category}:\n{query}\n")

def save_to_file(dorks, filename):
    with open(filename, 'w') as file:
        for category, query in dorks.items():
            file.write(f"{category}:\n{query}\n\n")
    print(f"Dorks saved to {filename}")

if __name__ == "__main__":
    domain = input("Enter a domain: ")
    dorks = generate_dorks(domain)
    display_dorks(dorks)
    
    save_option = input("Do you want to save these dorks to a text file? (y/n): ").lower()
    if save_option in ["yes", "y"]:
        filename = input("Enter the filename (with .txt extension): ")
        save_to_file(dorks, filename)
    else:
        print("Dorks not saved.")