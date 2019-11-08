from androguard.misc import AnalyzeAPK
from os import listdir
from os.path import isfile, join



apk_path = 'APKs'
apks = [f for f in listdir(apk_path) if isfile(join(apk_path, f))]


with open('spoofing_apks.txt', 'a+') as spoofing_apks_file:
    for i, apk in enumerate(apks):
        print("{}/{}".format(i, len(apks)))
        a, d, dx = AnalyzeAPK(join(apk_path, apk))
        for c in dx.get_classes():
            #if 'Landroid/webkit/WebSettings' in c.name: continue
            for meth in c.get_methods():
                if meth.name == 'setUserAgentString':
                    print("Class: {} \t APK: {}".format(c.name, apk))
                    spoofing_apks_file.write("\n")
                    spoofing_apks_file.write("Class: {} \t APK: {}\n".format(c.name, apk))
                    for _, call, _ in meth.get_xref_from():
                        print("  called by -> {} -- {}".format(call.class_name, call.name))
                        spoofing_apks_file.write("  called by -> {} -- {}\n".format(call.class_name, call.name))
                    spoofing_apks_file.write("\n")
                    continue
