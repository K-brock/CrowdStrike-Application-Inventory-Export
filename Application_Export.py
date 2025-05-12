from falconpy import Hosts, NGSIEM
from dotenv import load_dotenv
import os
import logging
import time
import csv
from datetime import datetime

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('host_inventory.log'),
        logging.StreamHandler()
    ]
)

class ApplicationInventory:
    def __init__(self):
        load_dotenv()
        self.api_key = os.getenv("API_KEY")
        self.api_secret = os.getenv("API_SECRET")
        self.falcon_cloud = os.getenv('FALCON_CLOUD', 'us-2')
        
        if not all([self.api_key, self.api_secret]):
            raise EnvironmentError("API_KEY and API_SECRET must be set in environment variables")
        
        self.falcon_hosts = Hosts(
            client_id=self.api_key,
            client_secret=self.api_secret,
            base_url=f"https://api.{self.falcon_cloud}.crowdstrike.com"
        )
        
        self.falcon_siem = NGSIEM(
            client_id=self.api_key,
            client_secret=self.api_secret
        )

    def convert_timestamp_ms(self, ms_timestamp):
        """Convert millisecond timestamp to readable format"""
        return datetime.fromtimestamp(int(ms_timestamp)/1000).strftime('%Y-%m-%d %H:%M:%S')

    def convert_timestamp_s(self, s_timestamp):
        """Convert second timestamp to readable format"""
        try:
            return datetime.fromtimestamp(float(s_timestamp)).strftime('%Y-%m-%d %H:%M:%S')
        except:
            return s_timestamp

    def get_device_aids(self):
        """Fetch all device AIDs from CrowdStrike API"""
        aids = []
        offset = None
        
        try:
            while True:
                response = self.falcon_hosts.query_devices_by_filter_scroll(
                    offset=offset,
                    limit=5000,
                    sort="hostname.asc"
                )
                
                if response["status_code"] != 200:
                    logging.error(f"Error querying devices: {response['body']}")
                    break
                    
                if response['body']['resources']:
                    details = self.falcon_hosts.get_device_details(ids=response['body']['resources'])
                    
                    if details["status_code"] == 200:
                        for device in details['body']['resources']:
                            if device.get('device_id'):
                                aids.append(device['device_id'])
                                logging.info(f"Found AID: {device['device_id']} for host: {device.get('hostname', 'Unknown')}")
                    
                offset = response['body'].get('offset')
                if not offset:
                    break
                    
        except Exception as e:
            logging.error(f"Error fetching devices: {str(e)}")
            
        return aids

    def query_installed_applications(self, aid, writer):
        """Query installed applications for a specific AID"""
        logging.info(f"Querying applications for AID: {aid}")
        
        test_search = {
            "isLive": False,
            "start": "30d",
            "queryString": f'#event_simpleName=InstalledApplication | aid = {aid} | groupBy([AppName], function=selectLast([@timestamp, ComputerName, aid, AppVendor, AppVersion, InstallDate])) | sort(InstallDate, order=desc, limit=20000)',
        }

        try:
            response = self.falcon_siem.start_search(
                repository="search-all",
                search=test_search,
                is_live=False,
                start="30d",
            )

            search_id = response['resources']['id']
            time.sleep(3)  # Wait for search to be ready

            results = self.falcon_siem.get_search_status(
                repository="search-all", 
                search_id=search_id
            )

            for event in results['body']['events']:
                event['@timestamp'] = self.convert_timestamp_ms(event['@timestamp'])
                if 'InstallDate' in event:
                    event['InstallDate'] = self.convert_timestamp_s(event['InstallDate'])

                row = {header: event.get(header, '') for header in self.headers}
                writer.writerow(row)

        except Exception as e:
            logging.error(f"Error querying applications for AID {aid}: {str(e)}")

    def run_inventory(self):
        """Run the complete inventory process"""
        self.headers = ['AppName', '@timestamp', 'ComputerName', 'aid', 'AppVendor', 'AppVersion', 'InstallDate']
        output_file = "installed_applications.csv"

        # Get all AIDs
        aids = self.get_device_aids()
        logging.info(f"Found {len(aids)} devices")

        # Create CSV file and write applications for each AID
        with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=self.headers)
            writer.writeheader()
            
            for aid in aids:
                self.query_installed_applications(aid, writer)

        logging.info(f"Inventory complete. Data written to {output_file}")

def main():
    try:
        inventory = ApplicationInventory()
        logging.info("Starting application inventory...")
        inventory.run_inventory()
        
    except Exception as e:
        logging.error(f"Fatal error in main execution: {str(e)}")

if __name__ == "__main__":
    main()
