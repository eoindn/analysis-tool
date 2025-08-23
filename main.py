from androguard.core.apk import APK
import os


filename = "calculator.apk"


def analyse_file():

    path = input("Enter path to APK file")
    try:
        apk = APK(path)
        permissions = apk.get_permissions()
        app_name = apk.get_app_name()
        package_name = apk.get_package()



        print(f"The APK '{apk}' contains the following permission: {permissions}")
        providers = apk.get_providers()
        print(f"Providers: {providers}")
        print(f"Package: {package_name}")
        print(f"Total permissions: {len(permissions)}")

        #filter out dangerous permissions
        dangerous_permissions =[p for p in permissions if "CAMERA" in p or "MICROPHONE" in p or "LOCATION" in p]
        if dangerous_permissions:
            print("Potentially dangerous and/or sensitive permissions found")
            for perm in dangerous_permissions:
                print(f"{perm} \n")
            else:print("No dangerous permissions found :)")

    except Exception as e:
        print(f"Erorr locating path {path} maybe check the spelling")


for filename in os.listdir('.'):
    if filename.endswith('.apk'):
        analyse_file(filename)



analyse_file()