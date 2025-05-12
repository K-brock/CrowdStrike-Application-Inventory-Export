# **CrowdStrike Application Inventory Export** 🛡️
> ⚠️ This tool is personally developed and is not supported, maintained, or endorsed by CrowdStrike. Use at your own risk, or do not use.

*Export all installed applications across all hosts into a single CSV for auditing. Each row represents an application and specificies the host its installled across*

---

## **Prerequisites** ✅

- Python 3.6+  
- CrowdStrike Falcon API credentials
- API Scopes [NGSIEM:read / write] [hosts:read]

---

## **Required Python Packages** 📦

- `falconpy`  
- `python-dotenv`  

---

## **Installation** 🧰

**Clone this repository:**
```bash
git clone https://github.com/K-brock/CrowdStrike-Application-Inventory-Export
```

**Install required packages:**
```bash
pip install -r requirements.txt
```

**Create a `.env` file in the project directory with your CrowdStrike API credentials:**
```dotenv
API_KEY='your_crowdstrike_client_id'
API_SECRET='your_crowdstrike_client_secret'
FALCON_CLOUD='us-2'  # Change to your appropriate region (us-1, us-2, eu-1, etc.)
```

---

### **Usage** 🚀

Run the script once to generate the installed_applications CSV:
```bash
python Application_Export.py
```

The script will:

- Iterate through each device AID 
- Run an NGSIEM query to pulldown all installed applications (takes around 3 seconds)
- Append data to spreadsheet

---

### **Logging**

The script logs all activity.

---

## **License** 📄

MIT License

---

## **Acknowledgments** 🙏

This tool uses the [FalconPy SDK](https://github.com/CrowdStrike/falconpy) provided by CrowdStrike.
