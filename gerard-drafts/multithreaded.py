from androguard.core.analysis import auto
import sys

class AndroTest(auto.DirectoryAndroAnalysis):
    def __init__(self, path):
       super(AndroTest, self).__init__(path)
       self.has_crashed = False

    def analysis_app(self, log, apkobj, dexobj, analysisobj):
        # Just print all objects to stdout
        print(log.id_file, log.filename, apkobj, dexobj, analysisobj)

    def finish(self, log):
       # This method can be used to save information in `log`
       # finish is called regardless of a crash, so maybe store the
       # information somewhere
       if self.has_crashed:
          print("Analysis of {} has finished with Errors".format(log))
       else:
          print("Analysis of {} has finished!".format(log))

    def crash(self, log, why):
       # If some error happens during the analysis, this method will be
       # called
       self.has_crashed = True
       print("Error during analysis of {}: {}".format(log, why), file=sys.stderr)

settings = {
    # The directory `some/directory` should contain some APK files
    "my": AndroTest('6test'),
    # Use the default Logger
    "log": auto.DefaultAndroLog,
    # Use maximum of 2 threads
    "max_fetcher": 6,
}

aa = auto.AndroAuto(settings)
aa.go()