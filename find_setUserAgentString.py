from androguard.misc import AnalyzeAPK
from os import listdir
from os.path import isfile, join



apk_path = 'APKs'
apks = [f for f in listdir(apk_path) if isfile(join(apk_path, f))]


with open('spoofing_apks.txt', 'a+') as spoofing_apks_file:
    for apk in apks:
        a, d, dx = AnalyzeAPK(join(apk_path, apk))
        if not 'Landroid/webkit/WebSettings;' in dx.classes: continue
        for meth in dx.classes['Landroid/webkit/WebSettings;'].get_methods():
            if meth.name == 'setUserAgentString':
                print(apk)
                spoofing_apks_file.write("\n")
                spoofing_apks_file.write(apk)
                continue
