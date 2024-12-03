import shodan
import requests
import pandas as pd
import streamlit as st
import altair as alt
import json

# Shodan API Key
SHODAN_API_KEY = "KDuyIBmsJICw61wmoCEdYBFoEhddWxvW"  # Replace with your Shodan API Key
shodan_client = shodan.Shodan(SHODAN_API_KEY)

# CIRCL CVE API Base URL
CIRCL_CVE_API_URL = "https://cve.circl.lu/api/cve"

# Helper function to parse severity
def parse_severity(severity_data):
    if isinstance(severity_data, dict):
        return {
            "Availability": severity_data.get("availability", "Unknown"),
            "Confidentiality": severity_data.get("confidentiality", "Unknown"),
            "Integrity": severity_data.get("integrity", "Unknown"),
        }
    elif isinstance(severity_data, str):
        try:
            severity_obj = json.loads(severity_data)
            return parse_severity(severity_obj)
        except json.JSONDecodeError:
            return {"Availability": "Unknown", "Confidentiality": "Unknown", "Integrity": "Unknown"}
    return {"Availability": "N/A", "Confidentiality": "N/A", "Integrity": "N/A"}

# Helper function to categorize risk based on CVSS score
def categorize_risk(cvss_score):
    if cvss_score >= 9.0:
        return "Critical"
    elif cvss_score >= 7.0:
        return "High"
    elif cvss_score >= 4.0:
        return "Medium"
    elif cvss_score >= 0.0:
        return "Low"
    return "Unknown"

# Helper function to categorize vulnerability type based on CVE summary
def categorize_vulnerability_type(summary):
    summary = summary.lower()
    if 'buffer overflow' in summary:
        return 'Buffer Overflow'
    elif 'sql injection' in summary:
        return 'SQL Injection'
    elif 'cross-site scripting' in summary or 'xss' in summary:
        return 'Cross-site Scripting'
    elif 'command injection' in summary or 'code injection' in summary:
        return 'Code Injection'
    elif 'remote code execution' in summary or 'rce' in summary:
        return 'Remote Code Execution'
    elif 'denial of service' in summary or 'dos' in summary:
        return 'Denial of Service'
    elif 'information disclosure' in summary or 'data leak' in summary:
        return 'Information Disclosure'
    elif 'privilege escalation' in summary or 'elevation of privilege' in summary:
        return 'Privilege Escalation'
    elif 'authentication bypass' in summary or 'bypass authentication' in summary:
        return 'Authentication Bypass'
    elif 'directory traversal' in summary or 'path traversal' in summary:
        return 'Directory Traversal'
    elif 'security misconfiguration' in summary or 'misconfiguration' in summary:
        return 'Security Misconfiguration'
    elif 'man-in-the-middle' in summary or 'mitm' in summary:
        return 'Man-in-the-Middle'
    return 'Other'

# Step 1: Fetch IP Data from Shodan
def get_ip_info(ip_list):
    results = []
    for ip in ip_list:
        try:
            data = shodan_client.host(ip)
            vulns = data.get("vulns", [])
            for cve in vulns:
                results.append({
                    "IP": ip,
                    "CVE": cve,
                })
        except shodan.APIError as e:
            results.append({"IP": ip, "Error": str(e)})
    return results

# Fetch CVE Details from CIRCL (with updated severity parsing)
def get_cve_details_from_circl(cve_ids):
    cve_details = []
    for cve_id in cve_ids:
        try:
            response = requests.get(f"{CIRCL_CVE_API_URL}/{cve_id}")
            if response.status_code == 200:
                cve_data = response.json()
                severity = cve_data.get("severity", {})
                parsed_severity = parse_severity(severity)  # Parse severity data
                
                # Extract CVSS score
                cvss_score = cve_data.get("cvss", "N/A")
                try:
                    cvss_score = float(cvss_score)
                except ValueError:
                    cvss_score = 0.0

                # Categorize Risk
                risk = categorize_risk(cvss_score)

                # Categorize vulnerability type
                vulnerability_type = categorize_vulnerability_type(cve_data.get("summary", "N/A"))

                cve_details.append({
                    "CVE": cve_id,
                    "CVSS Score": cvss_score,
                    "Risk": risk,
                    "Description": cve_data.get("summary", "N/A"),
                    "Vulnerability Type": vulnerability_type  # Added vulnerability type
                })
        except Exception as e:
            continue

    return pd.DataFrame(cve_details)

# Update the Dashboard to Show Separate Severity Columns
def show_dashboard(ip_results):
    st.title("IP Monitoring and CVE Analytics Tool")

    # Display Raw Data
    df = pd.DataFrame(ip_results)
    st.write("### IP and CVE Information")
    st.dataframe(df)

    # Extract Unique CVEs and Get Details
    cve_ids = df["CVE"].dropna().unique()
    if len(cve_ids) > 0:
        cve_data = get_cve_details_from_circl(cve_ids)
        st.write("### CVE Details")
        st.dataframe(cve_data)

        # Pie Chart for Vulnerability Type Distribution with Percentages
        st.write("### Vulnerability Type Distribution")
        if "Vulnerability Type" in cve_data.columns:
            vuln_type_counts = cve_data['Vulnerability Type'].value_counts().reset_index()
            vuln_type_counts.columns = ['Vulnerability Type', 'Count']
            
            # Calculate the percentage of each type
            total_count = vuln_type_counts['Count'].sum()
            vuln_type_counts['Percentage'] = (vuln_type_counts['Count'] / total_count) * 100
            
            # Create the pie chart
            pie_chart = alt.Chart(vuln_type_counts).mark_arc().encode(
                theta='Count:Q',
                color='Vulnerability Type:N',
                tooltip=['Vulnerability Type:N', 'Count:Q', 'Percentage:Q'],
            ).properties(title="Vulnerability Type Distribution")

            st.altair_chart(pie_chart, use_container_width=True)

            # Display vulnerability types with percentages below the chart
            st.write("### Vulnerability Types and Percentages")
            vuln_type_counts['Percentage'] = vuln_type_counts['Percentage'].round(1).astype(str) + '%'
            st.dataframe(vuln_type_counts[['Vulnerability Type', 'Percentage']])

        # CVE Severity Chart (unchanged)
        st.write("### CVE Severity Chart")
        if "CVSS Score" in cve_data:
            chart = alt.Chart(cve_data).mark_bar().encode(
                x='CVSS Score:Q',
                y='count():Q',
                color='Risk:N'
            ).properties(title="CVE CVSS Score Distribution by Risk")
            st.altair_chart(chart, use_container_width=True)
    else:
        st.warning("No CVEs found to analyze.")

# Main Function to Run the App
def main():
    st.sidebar.title("IP Monitoring Tool")
    ip_input = st.sidebar.text_area("Enter IP addresses (comma-separated)", placeholder="192.168.0.1, 8.8.8.8")
    ip_list = [ip.strip() for ip in ip_input.split(",") if ip.strip()]

    if st.sidebar.button("Analyze"):
        st.sidebar.write("Fetching data...")
        ip_results = get_ip_info(ip_list)
        show_dashboard(ip_results)

if __name__ == "__main__":
    main()
