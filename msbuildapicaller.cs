using Microsoft.Build.Construction;
using Microsoft.Build.Evaluation;
using Microsoft.Build.Execution;
using Microsoft.Build.Logging;
using Microsoft.Build.Framework;
using Microsoft.Build.Utilities;
using System.Xml;
using System.Collections;
using System.Collections.Generic;
using System;
using System.IO;

/*
Build with following command
C:\Windows\Microsoft.Net\Framework\v4.0.30319\csc.exe /reference:"Microsoft.Build.Framework.dll";"Microsoft.Build.dll";"Microsoft.Build.Engine.dll";"Microsoft.Build.Utilities.v4.0.dll";"System.Runtime.dll" /target:exe msbuildapicaller.cs
*/


namespace MSBuildAPICaller {

    public class BuildIt
    {
        private static bool BuildProject(string projectPath)
            {
                // Uncomment for logging
                //var logPath = Path.Combine(Path.GetDirectoryName(projectPath), "build.log");

                //.Net 4 Microsoft.Build.Evaluation.Project and ProjectCollection
                var engine = new ProjectCollection();


                /* Uncomment for logging    
                // Instantiate a new FileLogger to generate build log
                var logger = new Microsoft.Build.Logging.FileLogger();

                // Set the logfile parameter to indicate the log destination
                logger.Parameters = @"logfile=" + logPath;
                // Register the logger with the engine
                engine.RegisterLogger(logger);
                */
                // Build a project file
                bool success = engine.LoadProject(projectPath).Build();
                //Uncomment for logging
                //Unregister all loggers to close the log file
                //engine.UnregisterAllLoggers();

                //if fails, put the log file into the assert statement
                string txt = "Finished!";
                /* Uncomment for logging
                if (!success && File.Exists(logPath))
                    txt = File.ReadAllText(logPath);
                 */   
                Console.WriteLine(txt);

                return success;
            }
        
        static void Main(string[] args)
        {   
        string projectPath = "msbuildapicaller.csproj";
        BuildProject(projectPath);
        }
    }
}
