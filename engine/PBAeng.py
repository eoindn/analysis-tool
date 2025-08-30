import json
from datetime import datetime
from androguard.core.apk import APK


class PermissionBehaviourAnalyser:
    def __init__(self):
        self.static_data = {}
        self.dynamic_data = {}
        self.correlations = {}

    def analyse_file(self,apk_path):

        try:
            apk = APK(apk_path)
            app_name = apk.get_app_name()

            static_analysis =  {
                "app_name": apk.get_app_name(),
                "package_name": apk.get_package(),
                "permissions": apk.get_permissions(),
                "internet_permissions" : 'android.permission.INTERNET' in apk.get_permissions(),
                "location_permissions": [p for p in apk.get_permissions() if 'LOCATION' in p],
                "camera_permissions": [p for p in apk.get_permissions() if 'CAMERA' in p],
                "contacts_permissions": [p for p in apk.get_permissions() if 'CONTACTS' in p],
                "microphone_permissions" : [p for p in apk.get_permissions() if 'MICROPHONE' in p],
                'total_permissions': len(apk.get_permissions())
            }
            self.static_data[app_name] = static_analysis
            return static_analysis

        except Exception as e:
            print(f"Error analysing APK: {e}")
            return None


    def load_dynamic_data(self,network_data_path):
        #load data from the json file that was made from the last dynamic traffic analysis
        try:
            with open('network_path' 'r') as f:
                dynamic_analysis = json.load(f)

            app_name = dynamic_analysis['app_name']
            self.dynamic_data['app_name'] = dynamic_analysis
            return dynamic_analysis
        except Exception as e:
            print(f"Error loading the network_data {e}")

        return dynamic_analysis




