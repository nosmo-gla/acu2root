import pandas as pd
from bs4 import BeautifulSoup
import re
from datetime import datetime
import argparse
import os

"""
Tool for pentest reports to create tables of affected cookies from Acunetix CSV vulnerability exports.

-nosmo
"""

def extract_cookie_data(details, filter_name):
    soup = BeautifulSoup(details, "html.parser")
    output_rows = []
    
    for li in soup.find_all("li"):  # Each list entry corresponds to one output row
        endpoint = li.text.split(" ")[0].strip()  # Extract URL after <li>
        pre_tags = li.find_all("pre")
        
        if filter_name == "Cookies with missing, inconsistent or contradictory properties":
            if len(pre_tags) >= 2:
                cookie_text = pre_tags[0].text.strip()
                issues_text = pre_tags[1].text.strip()
                match = re.search(r"Set-Cookie:\s*([^=]+)=.*?[pP]ath=([^;]+)", cookie_text)
                
                if match:
                    cookie_name, affected_path = match.groups()
                    issues = "\n".join(re.findall(r"- (.*)", issues_text))  # Extract issue lines without leading '-'
                    output_rows.append((endpoint, cookie_name, affected_path, issues))
        
        else:
            if pre_tags:
                cookie_text = pre_tags[0].text.strip()
                match = re.search(r"Set-Cookie:\s*([^=]+)=.*?[pP]ath=([^;]+)", cookie_text)
                
                if match:
                    cookie_name, affected_path = match.groups()
                    output_rows.append((endpoint, cookie_name, affected_path))
    
    return output_rows

def process_csv(input_file, filter_name, output_file, remove_duplicates):
    df = pd.read_csv(input_file, dtype=str)
    
    # Filter rows where the relevant column contains the target value
    filtered_df = df[df['Name'] == filter_name]
    
    output_data = []
    
    if filter_name == "Cross-site Scripting":
        for _, row in filtered_df.iterrows():
            hostname = row['Target'].strip('/')  # Extract Hostname
            affected_path = row['Affects']  # Extract Affected Path
            parameter_name = row['Parameter']  # Extract Parameter Name
            output_data.append([hostname, affected_path, parameter_name])
    else:
        for _, row in filtered_df.iterrows():
            hostname = row['Target'].strip('/')  # Extract Hostname
            details = row['Details']  # Extract HTML details
            
            extracted_entries = extract_cookie_data(details, filter_name)
            
            for entry in extracted_entries:
                if filter_name == "Cookies with missing, inconsistent or contradictory properties":
                    endpoint, cookie_name, affected_path, issues = entry
                    output_data.append([hostname, endpoint.replace(hostname, ""), cookie_name, affected_path, issues])
                else:
                    endpoint, cookie_name, affected_path = entry
                    output_data.append([hostname, endpoint.replace(hostname, ""), cookie_name, affected_path])
    
    if filter_name == "Cross-site Scripting":
        columns = ["Hostname", "Affected Path", "Parameter Name"]
    else:
        columns = ["Hostname", "Endpoint", "Cookie Name", "Affected Path"]
        if filter_name == "Cookies with missing, inconsistent or contradictory properties":
            columns.append("Issues")
    
    output_df = pd.DataFrame(output_data, columns=columns)
    
    if remove_duplicates:
        output_df = output_df.drop_duplicates()
    
    output_df.to_csv(output_file, index=False)
    return output_file

def main():
    parser = argparse.ArgumentParser(description="Process security issues from Acunetix CSV files.")
    parser.add_argument("--inputfile", "-i", required=True, help="Path to the input CSV file.")
    parser.add_argument("--outputfolder", "-o", required=False, help="Directory to save the output CSV file.")
    parser.add_argument("--cookiehttp", action="store_true", help="Filter for 'Cookies Not Marked as HttpOnly'.")
    parser.add_argument("--cookiesecure", action="store_true", help="Filter for 'Cookies Not Marked as Secure'.")
    parser.add_argument("--cookieinconsistent", action="store_true", help="Filter for 'Cookies with missing, inconsistent or contradictory properties'.")
    parser.add_argument("--XSS", "-x", action="store_true", help="Filter for 'Cross-site Scripting'.")
    parser.add_argument("--unique", "-u", action="store_true", help="Remove duplicate entries from the output file.")
    
    args = parser.parse_args()
    
    if args.cookiehttp:
        filter_name = "Cookies Not Marked as HttpOnly"
    elif args.cookiesecure:
        filter_name = "Cookies Not Marked as Secure"
    elif args.cookieinconsistent:
        filter_name = "Cookies with missing, inconsistent or contradictory properties"
    elif args.XSS:
        filter_name = "Cross-site Scripting"
    else:
        print("Error: Please provide a valid filter flag.")
        return
    
    timestamp = datetime.now().strftime("%y%m%d%H%M%S")
    output_filename = f"{filter_name.replace(' ', '_')}_{timestamp}.csv"
    output_folder = args.outputfolder if args.outputfolder else os.getcwd()
    output_path = os.path.join(output_folder, output_filename)
    
    output_filepath = process_csv(args.inputfile, filter_name, output_path, args.unique)
    print(f"Output saved to: {output_filepath}")

if __name__ == "__main__":
    main()
