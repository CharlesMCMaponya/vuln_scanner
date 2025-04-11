from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError

def send_slack_alert(cve_results):
    # Replace with your Slack bot token and channel
    slack_token = "your-slack-bot-token"
    channel = "#alerts"
    client = WebClient(token=slack_token)
    message = "Vulnerability Alert!\n"
    for cve in cve_results:
        message += f"{cve['cve_id']}: {cve['description']} (Severity: {cve['severity']})\n"
    try:
        client.chat_postMessage(channel=channel, text=message)
        print("Slack alert sent!")
    except SlackApiError as e:
        print(f"Error sending Slack alert: {e}")

