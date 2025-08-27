from androguard.core.apk import APK
import os
import json
from datetime import datetime

from sqlalchemy.testing.config import ident

filename = "calculator.apk"


def calculate_risk(app_data):
    score = 0
    dangerous_perms = app_data['dangerous_permissions']
    score += len(dangerous_perms) * 3
    score += max(0, app_data['total_permissions'] - 10)

    super_dangerous_permissions = app_data['critical_permissions']
    score += sum(3 for p in dangerous_perms if any(risk in p for risk in super_dangerous_permissions))

    if score < 40:
        print("Apps permissions are generally safe")
    else:print(f"App contains permissions that may risk sensitive data\n Dangerous Permissions:{len(dangerous_perms)}\n"
               f"Critical Permissions:{len(super_dangerous_permissions)}"
               )

    return min(score,100)


def compare_apps(app_data1, app_data2):
    print(f"\n=== COMPARING APPS ===")
    print(f"App 1: {app_data1['app_name']}")
    print(f"App 2: {app_data2['app_name']}")

    # Compare total permissions
    print(f"\nTotal Permissions:")
    print(f"  {app_data1['app_name']}: {app_data1['total_permissions']}")
    print(f"  {app_data2['app_name']}: {app_data2['total_permissions']}")

    # Compare risk scores (you'll need to store this in app_data)
    print(f"\nRisk Scores:")
    print(f"  {app_data1['app_name']}: {app_data1.get('risk_score', 'Not calculated')}")
    print(f"  {app_data2['app_name']}: {app_data2.get('risk_score', 'Not calculated')}")

    # Simple winner
    if app_data1['total_permissions'] < app_data2['total_permissions']:
        print(f"\n🏆 {app_data1['app_name']} appears safer (fewer permissions)")
    else:
        print(f"\n🏆 {app_data2['app_name']} appears safer (fewer permissions)")




def analyse_file(path):


    try:
        apk = APK(path)
        app_data = {
            'filename': path,
            'app_name': apk.get_app_name(),
            'package_name': apk.get_package(),
            'version': apk.get_androidversion_name(),
            'permissions': apk.get_permissions(),
            'total_permissions': len(apk.get_permissions()),
            'analyzed_date': datetime.now().isoformat()
        }


        #filter out dangerous permissions
        dangerous_keywords = ['CAMERA','LOCATION','MICROPHONE','CONTACTS','SMS','PHONE']
        critical_keywords = ['READ_CONTACTS','ACCESS_FINE_LOCATION','RECORD_AUDIO','CAMERA']
        app_data['dangerous_permissions'] = [
            perm for perm in app_data['permissions'] if any (keyword in perm for keyword in dangerous_keywords)
        ]
        app_data['critical_permissions'] = [perm for perm in app_data['permissions'] if any(keyword in perm for keyword in critical_keywords)]

        app_data['risk_score'] = calculate_risk(app_data)

        print(f"Analysed: {app_data['app_name']} with {len(app_data['permissions'])} permissions")
        print(f"App safety score: {calculate_risk(app_data)}")

        compare_apps()



        with open("results.txt","a") as f:
            print(f"Text file results for {app_data['app_name']}\n")
            print(f"Analysed: {app_data['app_name']} with {len(app_data['permissions'])} permissions",file=f)
            print(f"App safety score: {calculate_risk(app_data)}",file=f)
            f.close()


        return app_data




    except Exception as e:
        print(f"Error locating path {path} maybe check the spelling")






results = []
apk_files = [f for f in os.listdir() if f.endswith('.apk')]
print(f"Found {len(results)} APK files ready for analysis")


for apk_file in apk_files:
    result = analyse_file(apk_file)
    if result:
        results.append(result)

if len(results) >= 2:
    compare_apps(results[0],results[1])

        #save to json

outputfile = f"app_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
with open(outputfile,'w') as f:
    json.dump(results,f,indent=2)

print(f"Results successfully saved to: {outputfile}")
print(f"Analysed {len(results)} app successfully")

if results:
    avg_permissions = sum(app['total_permissions'] for app in results) / len(results)
    most_permissions = max(results, key=lambda x: x['total_permissions'])

    print(f"📈 Average permissions per app: {avg_permissions:.1f}")
    print(f"🏆 Most permissions: {most_permissions['app_name']} ({most_permissions['total_permissions']})")


