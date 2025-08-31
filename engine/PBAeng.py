import json
from datetime import datetime
from androguard.core.apk import APK
import os


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
            with open(network_data_path, 'r') as f:
                dynamic_analysis = json.load(f)

            app_name = dynamic_analysis['app_name']
            self.dynamic_data[app_name] = dynamic_analysis
            return dynamic_analysis
        except Exception as e:
            print(f"Error loading the network_data {e}")
            return None


    def correlate_permissions(self,app_name):

        if app_name not in self.dynamic_data or app_name not in self.static_data:
            print(f"Error finding {app_name}")
            return None

        static = self.static_data[app_name]
        dynamic = self.dynamic_data[app_name]

        correlation = {
            'app_name': app_name,
            'date': datetime.now(),
            'findings': [],

        }

        #check if the app claims its requests network access and then see what it actually does
        needs_internet = static['internet_permission']
        made_requests = dynamic['domains_contacted']

        if needs_internet and not made_requests:
            correlation['findings'].append({
                'type':'unused_permission',
                'severity':'low',
                'description':f"App requests internet permission but makes no requests",
                'solution':'Consider removing this feature to maintain usability but protect against privacy concerns'
            })

        elif needs_internet and made_requests:
            correlation['findings'].append({
                'type': 'used_permission',
                'severity': 'low',
                'description': f"App made {dynamic['total_requests']} to {len(dynamic['domains_contacted'])}",
                'solution': 'The app appropriately uses its permissions'
            })

        elif not needs_internet and made_requests:
            correlation['findings'].append({
                'type': 'abuses_permission',
                'severity': 'high',
                'description': f"App doesnt request internet however made {dynamic['total_requests']} requests to {len(dynamic['domains_contacted'])}",
                'solution': 'Suggests the app analysis was interrupted or the app is not being transparent about the permissions it utilises'
            })



perm_anal = PermissionBehaviourAnalyser()
print(perm_anal.analyse_file('app.json'))
print(perm_anal.analyse_file('../calculator.apk'))
print(os.listdir('.'))



