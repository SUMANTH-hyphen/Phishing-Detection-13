import ipaddress
import re
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
from ipwhois import IPWhois
from datetime import date, datetime
from urllib.parse import urlparse

class FeatureExtraction:
    features = []
    def __init__(self,url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""

        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass

        try:
            self.urlparse = urlparse(url)
            self.domain = self.urlparse.netloc
        except:
            pass

        try:
            self.whois_response = IPWhois(socket.gethostbyname(self.domain)).lookup_whois()
        except:
            pass 

        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Https())
        

        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())
        self.features.append(self.LinksInScriptTags())
        self.features.append(self.ServerFormHandler())


        self.features.append(self.DNSRecording())
        self.features.append(self.WebsiteTraffic())
        self.features.append(self.GoogleIndex())
        self.features.append(self.LinksPointingToPage())



#+1   # 1.UsingIp 
    def UsingIp(self):
        try:
            ipaddress.IPv4Address(self.domain)
            return -1
        except ipaddress.AddressValueError:
            try:
                # If it fails, try to convert the components of a hexadecimal IP to integers
                hex_components = self.domain.split('.')
                decimal_components = [int(x, 16) for x in hex_components]
                # Create a dotted-decimal IP address
                dotted_decimal_ip = ".".join(map(str, decimal_components))
                # Validate the dotted-decimal IP address
                ipaddress.IPv4Address(dotted_decimal_ip)
                return -1
            except (ValueError, ipaddress.AddressValueError):
                return 1

#+2    # 2.longUrl
    def longUrl(self):
        if len(self.url) < 54:
            return 1
        if len(self.url) >= 54 and len(self.url) <= 75:
            return 0
        return -1
 
#+3    # 6.prefixSuffix
    def prefixSuffix(self):
        try:
            match = re.findall('\-', self.domain)
            if match:
                return -1
            return 1
        except:
            return -1
    
#+4    # 7.SubDomains
    def SubDomains(self):
        dot_count = self.url.count(".")
        print(dot_count)
        if dot_count == 2 or dot_count == 3:
            return 1
        elif dot_count > 2 and dot_count < 4 or dot_count == 1:
            return 0
        else:
            return -1

#+5    # 8.HTTPS
    def Https(self):
        try:
            https = self.urlparse.scheme
            if 'https' in https and 'https' not in self.domain and 'http' not in self.domain:
                return 1
            return -1
        except:
            return 1
 
#+6    # 13. RequestURL
    def RequestURL(self):
        try:
            success = 0
            i = 0

            for tag in ['img', 'audio', 'embed', 'iframe']:
                for element in self.soup.find_all(tag, src=True):
                    if self.urlparse.netloc in urlparse(element['src']).netloc or len(urlparse(element['src']).netloc.split('.')) == 1:
                        success += 1
                    i += 1

            # Calculate the percentage
            if i > 0:
                percentage = (success / i) * 100
                if percentage < 22.0 or percentage == 100.0:
                    print("(re) legitimate", percentage)
                    return 1  # Legitimate
                elif 22.0 <= percentage < 61.0:
                    print("(re) suspicious", percentage)
                    return 0  # Suspicious
                else:
                    print("(re) phishing", percentage)
                    return -1  # Phishing
            else:
                print("(re) No objects found")
                return 0  # Phishing if no objects found
        except ZeroDivisionError:
            print("(re) Division by zero")
            return 0
        except Exception as e:
            print(f"(re) An error occurred: {e}")
            return -1  # Phishing if an error occurs
   
#+7    # 14. AnchorURL
    def AnchorURL(self):
        try:
            i,unsafe = 0,0
            for a in self.soup.find_all('a', href=True):
                # Check if href attribute exists and is not empty
                if 'href' in a.attrs and a['href']:
                    href_lower = a['href'].lower()
                    # Check for unsafe anchor links
                    if "#" in href_lower or "javascript" in href_lower or "mailto" in href_lower or not (self.url in href_lower or self.domain in href_lower) :
                        if not re.match('^/.*$', href_lower):
                            unsafe += 1
                    i += 1
            # Calculate percentage and classify based on rules
            if i > 0:
                percentage = (unsafe / i) * 100
                if percentage < 31.0:
                    return 1  # Legitimate
                elif 31.0 <= percentage < 67.0:
                    return 0  # Suspicious
                else:
                    return -1  # Phishing
            else:
                return -1
        except:
            return -1

#+8    # 15. LinksInScriptTags
    def LinksInScriptTags(self):
        try:
            i, success = 0, 0
        
            for link in self.soup.find_all('link', href=True):
                if self.urlparse.netloc in link['href'] or len(urlparse(link['href']).netloc.split('.')) == 1:
                    success += 1
                i += 1

            for script in self.soup.find_all('script', src=True):
                if self.urlparse.netloc in script['src'] or len(urlparse(script['src']).netloc.split('.')) == 1:
                    success += 1
                i += 1

            # Check if no tags were found
            if i == 0:
                print("(li) No <link> or <script> tags found")
                return 0

            # Calculate percentage
            try:
                percentage = (success / i) * 100
                if percentage < 17.0:
                    print("(li) legitimate", percentage)
                    return 1
                elif 17.0 <= percentage < 81.0:
                    print("(li) not able to tell", percentage)
                    return 0
                else:
                    print("(li) phishing", percentage)
                    return -1
            except ZeroDivisionError:
                print("(li) Division by zero")
                return 0
        except Exception as e:
            print(f"(li) An error occurred: {e}")
            return -1

#+9    # 16. ServerFormHandler
    def ServerFormHandler(self):
        try:
            if len(self.soup.find_all('form', action=True))==0:
                return 1
            else :
                for form in self.soup.find_all('form', action=True):
                    if form['action'] == "" or form['action'] == "about:blank":
                        return -1
                    elif self.url not in form['action'] and self.domain not in form['action']:
                        return 0
                    else:
                        return 1
        except:
            return -1

#+10 
    def DNSRecording(self):
        try:
            # gethostbyname() requires only domain name as arg.
            # whois_info = IPWhois(socket.gethostbyname(self.domain)).lookup_whois()
            creation_date = self.whois_response["asn_date"]
            try:
                # Convert the creation_date string to a datetime object
                creation_date = datetime.strptime(creation_date, '%Y-%m-%d')
                
                # Get the current date
                current_date = datetime.now()
                
                # Calculate the age
                age = current_date.year - creation_date.year - ((current_date.month, current_date.day) < (creation_date.month, creation_date.day))
                details = self.whois_response["nets"][0]
                if details["emails"] is None:
                    return -1
                elif age >= 1 and details["description"] and details["address"] and details["postal_code"] and len(details["emails"]):
                    return 1
                else:
                    return -1
            except:
                -1
        except Exception as error:
            print(error)
            return -1

#+11    # 26. WebsiteTraffic   
    def WebsiteTraffic(self):
        try:
            api_key = "e019ecc4937f4135bb51e6e07582fc9b"
            # Extract domain from URL
            domain = self.url.replace("http://", "").replace("https://", "").replace("www.", "").split("/")[0]
            # Construct API URL
            api_url = f"https://api.similarweb.com/v1/similar-rank/{domain}/rank?api_key={api_key}"
            
            # Make the API request
            response = requests.get(api_url)
            
            # Check if request was successful
            if response.status_code == 200:
                data = response.json()
                rank = data.get('similar_rank', {}).get('rank')
                if rank is not None:
                    if rank < 100000:
                        print("Success")
                        print("1")
                        return 1
                    else:
                        return 0
                else:
                    print("Rank data not found in response")
                    return -1
            else:
                # Request was not successful
                print("API Error:", response.text)  # Print error message
                return -1
        except Exception as e:
            # Handle any exceptions
            print("Error:", e)
            return -1

#+12    # 28. GoogleIndex
    def GoogleIndex(self):
        try:
            # Fetch search results page directly
            search_url = f"https://www.google.com/search?q={self.url}"
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
            response = requests.get(search_url, headers=headers)
            response.raise_for_status()

            # Check if the URL appears in the search results
            if self.url in response.text:
                print("GI legitimate")
                return 1  # Legitimate
            else:
                print("Phishing")
                return -1  # Phishing
        except Exception as e:
            print("Error during Google Index check:", e)
            return -1  # Phishing
        
#+13    # 29. LinksPointingToPage
    def LinksPointingToPage(self):
        try:
            external_links = [link.get('href') for link in self.soup.find_all('a') if link.get('href') and not urlparse(link.get('href')).netloc.endswith(self.domain)]
            external_links_count = len(external_links)
            if external_links_count == 0:
                return -1
            elif external_links_count > 0 and external_links_count <= 2:
                return 0
            else:
                return 1
        except :
            return -1
    
   
    def getFeaturesList(self):
        print(self.features)
        return self.features
