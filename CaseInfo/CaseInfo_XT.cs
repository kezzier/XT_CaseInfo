using System;
using System.IO;
using System.Linq;
using Newtonsoft.Json;
using RGiesecke.DllExport;
using XTensions;
using System.Collections.Generic;
using Microsoft.Win32;

namespace CaseInfo
{
    public class CaseInfo_XT
    {
        public static Case current_case;
        public static IntPtr _hVolume;
        private static IntPtr _hEvidence;
        private static bool caseinfo_done;
        public static string sam_filename;
        public static string system_filename;
        public static string security_filename;
        private static string output_filename;
        public static bool caseusers;
        private static bool running;
        /*private static string report;*/
        public static bool hasvols;
        public static Partition current_part;
        public static string current_os;
        public static List<DateTime> installLogDates;
        public static string prefix_systemversion;
        public static string prefix;
        public static List<string> asl_files;
        public static List<DateTime> asl_dates;

        ///////////////////////////////////////////////////////////////
        /// X-Ways X-Tension calls
        /// 

        [DllExport]
        public static int XT_Init(CallerInformation nVersion, CallingProgramCapabilities nFlags, IntPtr hMainWnd, IntPtr lpReserved)
        {
            // If importing functions fails, we return -1 to prevent further use of the X-Tension.
            if (!ImportedMethods.Import())
            {
                HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: X-Tension CaseInfo - failed to import API methods.");
                return -1;
            }

            current_case = null;
            caseinfo_done = false;
            caseusers = false;
            running = false;
            /*report = "";*/

            return 1;
            
        }

        [DllExport]
        public static int XT_About(IntPtr hParentWnd, IntPtr lpReserved)
        {
            HelperMethods.OutputMessage("Get info about evidence objects for report.\n\nThis X-Tension can only be run from the menu or the tool bar.");
            return 0;
        }

        /// <summary>
        /// X-Tension must be initiated through menu or tool bar.
        /// Add every evidence object in case to 1 json string.
        /// </summary>
        /// <param name="nOpType">How X-Tension is initiated.</param> 
        [DllExport]
        public static int XT_Prepare(IntPtr hVolume, IntPtr hEvidence, XTensionActionSource nOpType, IntPtr lpReserved)
        {
            running = true;
            hasvols = false;
            _hVolume = hVolume;
            _hEvidence = hEvidence;
            sam_filename = null;
            system_filename = null;
            security_filename = null;
            installLogDates = new List<DateTime>();
            prefix_systemversion = @"^";
            prefix = @"^";
            asl_dates = new List<DateTime>();
            asl_files = new List<string>();

            if (nOpType == XTensionActionSource.VolumeSnapshotRefinement)
            {
                HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: Starting CaseInfo X-Tension for volume.");

                // only do caseinfo part once instead of per volume RVS
                if (!caseinfo_done)
                {
                    current_case = new Case(HelperMethods.GetCaseProperties().CaseTitle);

                    // get output file name
                    output_filename = HelperMethods.GetUserInput("Enter output file name (+ path) or Cancel for default", "");
                    if (output_filename == "Clicked cancel") output_filename = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Desktop), $"{current_case.Title}_json.txt");
                    if (!output_filename.EndsWith(".txt")) output_filename += ".txt";

                    /*// ask if user wants to run ReportAutomator at the end
                    report = CaseInfo_Methods.ChooseLanguage();*/

                    CaseInfo_Methods.ListEvObj(HelperMethods.GetCaseEvidence());                    
                    caseinfo_done = true;
                }

                current_part = Partition.GetPartition(_hEvidence);
                if (current_part != null)
                {
                    if (current_part.OS.Contains("Windows")) current_os = "Windows";
                    else if (current_part.Type == "APFS" || current_part.Type == "HFS+" || current_part.OS == "MacOS")
                    {
                        current_os = "MacOS";
                        if (current_part.Volumes.Count != 0)
                        {
                            prefix_systemversion = @"[^\\]+";
                            if (current_part.Volumes.Any(v => v.Label.Contains("-"))) prefix = @"[^\\]+-[^\\]+";
                            else prefix = @"[^\\]+";
                        }
                        else if (current_part.OS == "MacOS")
                        {
                            prefix_systemversion = @"[^\\]*";
                            prefix = @"[^\\]*";
                        }
                        return 0x21;
                    }
                    else
                    {
                        current_os = "Linux";
                        HelperMethods.PrepareTextAccess(PrepareTextAccess.DecodeText);
                    }
                }
                else current_os = null;

                return 1;
            }
            else
            {
                HelperMethods.OutputMessage("This X-Tension can only be run from Refine Volume Snapshot."); 
                return -3;
            }
        }

        [DllExport]
        public static long XT_ProcessItem(int nItemID, IntPtr lpReserved)
        {
            if (HelperMethods.ShouldStop())
            {
                HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: Stopping X-Tension");
                return -1;
            }

            if (current_os != null && HelperMethods.GetItemInformation(nItemID).deletionStatus == ItemDeletionStatus.Existing) {
                switch (current_os)
                {
                    case "Windows":
                        CaseInfo_Methods.CheckFileWindows(nItemID);
                        break;
                    case "MacOS":
                        CaseInfo_Methods.CheckFileMacOS(nItemID);
                        break;
                    case "Linux":
                        CaseInfo_Methods.CheckFileLinux(nItemID);
                        break;
                }
            }

            return 0;
        }

        [DllExport]
        public static int XT_Finalize(IntPtr hVolume, IntPtr hEvidence, XTensionActionSource nOpType, IntPtr lpReserved)
        {
            if (current_os == "Windows")
            {
                if (sam_filename != null)
                {
                    if (CaseInfo_Methods.Regripper() != 0) HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: " +
                             "RegRipper has failed/is unavailable; No users will be added.\n" +
                             "Please check that python is installed and is in %PATH% !\n");

                    if (system_filename != null)
                    {
                        if (security_filename != null)
                        {
                            if (CaseInfo_Methods.Impacket(true) != 0) HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: " +
                             "Impacket has failed/is unavailable; No domain users and/or hashes will be added.\n" +
                             "Please check that python and impacket are installed and are in %PATH% !\n");
                            File.Delete(security_filename);
                        }
                        else
                        {
                            if (CaseInfo_Methods.Impacket(false) != 0) HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: " +
                                "Impacket has failed/is unavailable; No hashes will be added to the users.\n" +
                                "Please check that python and impacket are installed and are in %PATH% !\n");
                        }
                        File.Delete(system_filename);
                    }
                    File.Delete(sam_filename);
                }
            }

            if (current_os == "MacOS")
            {
                if (installLogDates.Count > 0) current_part.Installation = installLogDates.Min(i => i).ToString("dd/MM/yyyy");
                if (asl_dates.Count > 0 && CaseInfo_Methods.ProcessAsl() != 0) HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: " +
                            "ccl-asl has failed/is unavailable; No user login or shutdown dates will be added.\n" +
                            "Please check that python is installed and is in %PATH% !\n");
            }

            HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: X-Tension CaseInfo finished for volume.");
            return 0;
        }

        [DllExport]
        public static int XT_Done(IntPtr lpReserved)
        {
            if (running)
            {
                string caseinfo_json = JsonConvert.SerializeObject(current_case);
                HelperMethods.OutputMessage($"Case Info (json): {caseinfo_json}");
                File.WriteAllText(output_filename, caseinfo_json);
                HelperMethods.OutputMessage($"[CaseInfo] JSON saved in {output_filename}");
                /*if (report != "cancel")
                {
                    string report_filename = output_filename.Substring(0, output_filename.Length-9);
                    if (CaseInfo_Methods.ReportAutomator(caseinfo_json, report, report_filename)) HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: report generated: {report_filename}_report.docx");
                    else HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: Unable to generate report");
                    HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: Unable to generate report");
                }*/
            }
            else HelperMethods.OutputMessage("[CaseInfo] Dll loaded!");
            return 0;
        }

    }
}
