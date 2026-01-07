using Claunia.PropertyList;
using Microsoft.Win32;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Security.Policy;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;
using System.Xml.Linq;
using XTensions;
using static System.Net.WebRequestMethods;

namespace CaseInfo
{
    class CaseInfo_Methods
    {

        private static string choice;

        ///////////////////////////////////////////////////////////////
        /// custom methods
        ///

        /// <summary>
        /// List all disks and partitions and add them to EvidenceObject current_case 
        /// </summary>
        /// <param name="evidence_list">IntPtr[] of all evidence objects</param>
        public static void ListEvObj(ArrayList evidence_list)
        {
            Disk current_disk = null;
            foreach (IntPtr eo in evidence_list)
            {
                var properties = HelperMethods.GetEvidenceObjectProperties(eo);
                // if eo is disk
                if (properties.FileSystemIdentifier.ToString() == "PartitionedDisks")
                {
                    current_disk = new Disk(properties);
                    CaseInfo_XT.current_case.Disks.Add(current_disk);
                }
                // if eo is partition; mainmemory = (used to be) hiberfil; viaos = directory 
                else if (new string[] { "MainMemory", "ViaOS" }.Contains(properties.FileSystemIdentifier.ToString()) == false && !properties.title.Contains("hiberfil"))
                {
                    Partition new_part = new Partition(properties);

                    // get first sector of partition in disk info
                    // no idea if try-catch is needed but this part of the code used to be in the following if(), idk why
                    // try-catch put here just in case there was a reason for it being inside the if()
                    try
                    {
                        var descr_array = current_disk.Properties.description.Split(new string[] { "\r\n\r\n" }, StringSplitOptions.None);
                        string p = Array.Find(descr_array, element => element.Contains(new_part.Name));
                        string[] p_info = (p == null) ? null : p.Split(new string[] { "\r\n" }, StringSplitOptions.None);
                        string fs_block = (p_info == null) ? "unknown" : Array.Find(p_info, element => element.Contains("Sectors"));
                        new_part.FirstSector = (fs_block == "unknown") ? fs_block : fs_block.Split(new string[] { " " }, StringSplitOptions.None)[1];
                    }
                    catch { }

                    if (current_disk != null && !properties.internalName.Contains(".ctr") && properties.parentObjectID != 0) current_disk.Partitions.Add(new_part);
                    else
                    {
                        CaseInfo_XT.current_case.Partitions.Add(new_part);
                        current_disk = null;
                    }

                }
            }
        }


        public static void CheckFileWindows(int nItemID)
        {
            string[] files = new string[4] { "SAM", "SYSTEM", "SECURITY", "SOFTWARE" };
            string filepath = "\\Windows\\System32\\config\\";

            string filename = HelperMethods.GetItemName(nItemID).ToUpper();
            if (files.Contains(filename))
            {
                if (String.Equals(HelperMethods.GetItemName(nItemID), filename, StringComparison.OrdinalIgnoreCase))
                {
                    // performance better when only opening needed file instead of all with processitemex
                    IntPtr hItem = HelperMethods.OpenItem(CaseInfo_XT._hVolume, nItemID);
                    // Equals means that this can only be run in an actual image (not from directory), not for a backup/SVC
                    if (HelperMethods.GetProp(hItem).Path.ToLower().Contains($"{filepath.ToLower()}{filename.ToLower()}"))
                    {
                        switch (filename)
                        {
                            case "SAM":
                                CaseInfo_XT.sam_filename = Prep_temp(hItem, ".reg");
                                break;
                            case "SYSTEM":
                                CaseInfo_XT.system_filename = Prep_temp(hItem, ".reg");
                                break;
                            case "SECURITY":
                                CaseInfo_XT.security_filename = Prep_temp(hItem, ".reg");
                                break;
                            case "SOFTWARE":
                                if (CaseInfo_XT.current_part.OS.Contains("Windows 10"))
                                {
                                    HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: Verifying Windows version...");
                                    if (CaseInfo_Methods.CheckWin11(hItem) != 0) HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: " +
                                        $"Unable to verify Windows version.\n");
                                }
                                break;
                        }

                    }
                }
            }
        }

        public static void CheckFileMacOS(int nItemID)
        {
            string[] filenames = new string[5] { "SystemVersion.plist", "preferences.plist", ".GlobalPreferences.plist", ".CFUserTextEncoding", ".AppleSetupDone" };
            if (filenames.Contains(HelperMethods.GetItemName(nItemID)))
            {
                // performance better when only opening needed file instead of all with processitemex
                IntPtr hItem = HelperMethods.OpenItem(CaseInfo_XT._hVolume, nItemID);

                string mac_ctr = @"";
                if (CaseInfo_XT.current_part.OS == "MacOS" && !CaseInfo_XT.hasvols) mac_ctr = SetVolumeRegex(hItem);

                if (!hItem.Equals(IntPtr.Zero))
                {
                    // OS + version
                    if (Regex.Match(HelperMethods.GetProp(hItem).Path, mac_ctr + CaseInfo_XT.prefix_systemversion + @"\\System\\Library\\CoreServices\\SystemVersion\.plist").Success)
                    {
                        var plist = Prep_plist(hItem, "plist");
                        CaseInfo_XT.current_part.OS = GetPlistValue(plist, "ProductName") + " " + GetPlistValue(plist, "ProductVersion");
                    }

                    // computername
                    else if (Regex.Match(HelperMethods.GetProp(hItem).Path, mac_ctr + CaseInfo_XT.prefix + @"\\Library\\Preferences\\SystemConfiguration\\preferences\.plist$").Success)
                    {
                        var plist = Prep_plist(hItem, "plist");
                        CaseInfo_XT.current_part.ComputerName = GetPlistValue(plist, "ComputerName");
                    }

                    // timezone
                    else if (Regex.Match(HelperMethods.GetProp(hItem).Path, mac_ctr + CaseInfo_XT.prefix + @"\\Library\\Preferences\\\.GlobalPreferences\.plist$").Success)
                    {
                        var plist = Prep_plist(hItem, "bplist");
                        CaseInfo_XT.current_part.Timezone = GetPlistValue(plist, "TimeZoneName");
                    }

                    // user dir -> username
                    else if (Regex.Match(HelperMethods.GetProp(hItem).Path, mac_ctr + CaseInfo_XT.prefix + @"\\Users\\[^\\]+\\\.CFUserTextEncoding$").Success)
                    {
                        string username = HelperMethods.GetItemName(HelperMethods.GetItemParent(nItemID));
                        if (User.GetUser(username) == null) CaseInfo_XT.current_part.Users.Add(new User(username));
                    }

                    // applesetupdone -> installation date
                    else if (Regex.Match(HelperMethods.GetProp(hItem).Path, mac_ctr + CaseInfo_XT.prefix + @"\\private\\var\\db\\.AppleSetupDone").Success)
                    {
                        CaseInfo_XT.installLogDates.Add(HelperMethods.GetItemInformation(nItemID).creationTime);
                    }

                    HelperMethods.CloseItem(hItem);
                }
            }

            // installation date
            else if (HelperMethods.GetItemName(nItemID).Contains("install.log"))
            {
                IntPtr hItem = HelperMethods.OpenItem(CaseInfo_XT._hVolume, nItemID);
                string mac_ctr = @"";
                if (CaseInfo_XT.current_part.OS == "MacOS" && !CaseInfo_XT.hasvols) mac_ctr = SetVolumeRegex(hItem);

                if (!hItem.Equals(IntPtr.Zero))
                {
                    if (Regex.Match(HelperMethods.GetProp(hItem).Path, mac_ctr + CaseInfo_XT.prefix + @"\\private\\var\\log\\install\.log*[^\\]$").Success)
                    {
                        CaseInfo_XT.installLogDates.Add(HelperMethods.GetItemInformation(nItemID).creationTime);
                    }
                    HelperMethods.CloseItem(hItem);
                }
            }

            else if (HelperMethods.GetItemName(nItemID).Contains(".plist"))
            {
                IntPtr hItem = HelperMethods.OpenItem(CaseInfo_XT._hVolume, nItemID);
                string mac_ctr = @"";
                if (!hItem.Equals(IntPtr.Zero))
                {
                    if (CaseInfo_XT.current_part.OS == "MacOS" && !CaseInfo_XT.hasvols) mac_ctr = SetVolumeRegex(hItem);
                    // user plist -> user info
                    if (Regex.Match(HelperMethods.GetProp(hItem).Path, mac_ctr + CaseInfo_XT.prefix + @"\\private\\var\\db\\dslocal\\nodes\\Default\\users\\[^_|nobody|root|daemon]+[^\\]+$").Success)
                    {
                        var plist = Prep_plist(hItem, "bplist");
                        var sid = GetPlistValue(plist, "generateduid");
                        var username = GetPlistValue(plist, "name");
                        var fullname = GetPlistValue(plist, "realname");
                        var hashtype = Get_split(Get_split(GetPlistValue(plist, "authentication_authority"), ";")[2], ":")[1].Replace("<", "").Replace(">", "");
                        var pwdHint = GetPlistValue(plist, "hint");
                        var hash = GetMacHash(hItem);

                        var currentuser = User.GetUser(username);
                        if (currentuser != null)
                        {
                            currentuser.SID = sid;
                            currentuser.FullName = fullname;
                            currentuser.HashType = hashtype;
                            currentuser.PwdHint = pwdHint;
                            currentuser.Hash = hash;
                        }
                        else
                        {
                            CaseInfo_XT.current_part.Users.Add(new User(sid, username, fullname, hash, hashtype, pwdHint));
                        }
                    }
                    HelperMethods.CloseItem(hItem);
                }
            }

            else if (HelperMethods.GetItemName(nItemID).Contains("asl"))
            {
                IntPtr hItem = HelperMethods.OpenItem(CaseInfo_XT._hVolume, nItemID);
                string mac_ctr = @"";
                if (CaseInfo_XT.current_part.OS == "MacOS" && !CaseInfo_XT.hasvols) mac_ctr = SetVolumeRegex(hItem);
                if (!hItem.Equals(IntPtr.Zero))
                {
                    // -> user last login + shutdown
                    if (Regex.Match(HelperMethods.GetProp(hItem).Path, mac_ctr + CaseInfo_XT.prefix + @"\\private\\var\\log\\asl\\BB\.[^\\]+$").Success)
                    {
                        CaseInfo_XT.asl_files.Add(Prep_temp(hItem, ".asl"));
                        CaseInfo_XT.asl_dates.Add(HelperMethods.GetItemInformation(nItemID).creationTime);
                    }
                    HelperMethods.CloseItem(hItem);
                }
            }
        }

        public static void CheckFileLinux(int nItemID)
        {
            string[] filenames = new string[6]
            {
                "os-release",
                "hostname",
                "timezone",
                "passwd",
                "lastlog",
                "shadow"
            };
            string[] filepaths = new string[3] {
                "\\etc\\",
                "\\var\\log\\",
                "\\usr\\lib\\"
            };

            string filename = HelperMethods.GetItemName(nItemID).ToLower();
            if (filenames.Contains(filename))
            {
                IntPtr hItem = HelperMethods.OpenItem(CaseInfo_XT._hVolume, nItemID);
                string path = Regex.Replace(HelperMethods.GetProp(hItem).Path.ToLower(), "os-release|hostname|timezone|passwd|lastlog|shadow", String.Empty);
                if (filepaths.Contains(path))
                {
                    string content = HelperMethods.GetText(hItem, GetTextOptions.DecodeText);
                    if (!content.Contains("ERROR")) switch (filename)
                        {
                            case "os-release":
                                foreach (string line in Get_split(content, "\r"))
                                {
                                    if (line.Contains("PRETTY_NAME")) CaseInfo_XT.current_part.OS = Get_split(line, "\"")[1];
                                }
                                break;
                            case "hostname":
                                CaseInfo_XT.current_part.ComputerName = content;
                                break;
                            case "timezone":
                                CaseInfo_XT.current_part.Timezone = content;
                                break;
                            case "passwd":
                                foreach (string line in Get_split(content, "\r"))
                                {
                                    var info = Get_split(line, ":");
                                    string SID = info[2];
                                    if (int.Parse(SID) >= 1000 && info[0] != "nobody")
                                    {
                                        string username = info[0];
                                        string fullname = Get_split(info[4], ",")[0];
                                        User u = User.GetUser(username);
                                        if (u == null)
                                        {
                                            CaseInfo_XT.current_part.Users.Add(new User(username));
                                            u = User.GetUser(username);
                                        }
                                        u.SID = SID;
                                        if (fullname != "") u.FullName = fullname;
                                    }
                                }
                                break;
                            case "lastlog":
                                // TODO
                                // read file - is text extractor or is it its own file format?
                                // to figure out
                                break;
                            case "shadow":
                                foreach (string line in Get_split(content, "\r"))
                                {
                                    var info = Get_split(line, ":");

                                    string username = info[0];
                                    User u = User.GetUser(username);

                                    string hash = info[1];
                                    string hashtype = "unknown";
                                    if (hash.StartsWith("$")) switch (Get_split(hash, "$")[1])
                                        {
                                            case "1":
                                                hashtype = "MD5";
                                                break;
                                            case "2a":
                                            case "2y":
                                                hashtype = "Blowfish";
                                                break;
                                            case "5":
                                                hashtype = "SHA-256";
                                                break;
                                            case "6":
                                                hashtype = "SHA-512";
                                                break;
                                        }

                                    if (u != null)
                                    {
                                        u.Hash = hash;
                                        u.HashType = hashtype;
                                    }
                                    else if (hashtype != "unknown") CaseInfo_XT.current_part.Users.Add(new User(username, hash, hashtype));
                                }
                                break;
                        }
                }
                HelperMethods.CloseItem(hItem);
            }
        }

        /// <summary>
        /// Prepare temp file with sam/system contents to use for processing.
        /// </summary>
        private static string Prep_temp(IntPtr hItem, string extension)
        {
            // create temp file 
            string filename = Path.GetTempFileName();
            System.IO.File.Move(filename, Path.ChangeExtension(filename, extension));
            filename = Path.ChangeExtension(filename, extension);
            FileInfo fi = new FileInfo(filename);
            fi.Attributes = FileAttributes.Temporary;

            // add data to temp file
            byte[] item_file = HelperMethods.ReadItem(hItem);
            System.IO.File.WriteAllBytes(filename, item_file);

            return filename;
        }

        /// <summary>
        /// ProductName of OS is not updated when installing Windows 11.
        /// Verify CurrentBuild of OS to see if it is >20000 which means it's Windows 11.
        /// If Win11, verify EditionID to get full ProductName.
        /// </summary>
        private static int CheckWin11(IntPtr hItem)
        {
            string software_filename = Prep_temp(hItem, ".reg");
            string cmd = $"& '{AppDomain.CurrentDomain.BaseDirectory}XTensions\\Tools\\RECmd.exe\' -f {software_filename} " +
                $"--kn \'Microsoft\\Windows NT\\CurrentVersion\' --vn CurrentBuild --nl";
            string[] oe = StartProcess("powershell.exe", cmd);

            if (oe[0] == "")
            {
                if (oe[1].Contains("CommandNotFoundException")) HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: " +
                    $"[ERROR] Unable to get Windows version. Please check if RECmd is in the Tools directory!");
                else HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: [ERROR] Powershell error message:\n{oe[1]}");
                return -1;
            }

            foreach (string line in Get_split(oe[0], "\r\n\r\n"))
            {
                if (line.Contains("Value"))
                {
                    foreach (string subline in Get_split(line, "\r\n"))
                    {
                        // check if win11
                        if (subline.Contains("Value data") && (Get_split(subline, ": ")[1].StartsWith("2")))
                        {
                            // get edition
                            string edition = GetWin11Edition(software_filename);
                            // set partition OS
                            CaseInfo_XT.current_part.OS = $"Windows 11 {edition}";
                        }
                    }
                }
            }

            return 0;
        }

        private static string GetWin11Edition(string software_filename)
        {
            string cmd = $"& '{AppDomain.CurrentDomain.BaseDirectory}XTensions\\Tools\\RECmd.exe\' -f {software_filename} " +
                $"--kn \'Microsoft\\Windows NT\\CurrentVersion\' --vn EditionID --nl";
            string[] oe = StartProcess("powershell.exe", cmd);

            if (oe[0] != "")
            {
                foreach (string line in Get_split(oe[0], "\r\n\r\n"))
                {
                    if (line.Contains("Value"))
                    {
                        foreach (string subline in Get_split(line, "\r\n"))
                        {
                            if (subline.Contains("Value data")) return Get_split(Get_split(subline, ": ")[1], " (")[0];
                        }
                    }
                }
            }

            if (oe[1].Contains("CommandNotFoundException")) HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: " +
                    $"[ERROR] Unable to get Windows edition. Please check if RECmd is in the Tools directory!");
            else HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: [ERROR] Powershell error message:\n{oe[1]}");
            return "";
        }

        private static XDocument Prep_plist(IntPtr hItem, string type)
        {
            var bytearray = HelperMethods.ReadItem(hItem);
            var xmlstring = "";

            try
            {
                if (type == "bplist")
                {
                    var parsed = BinaryPropertyListParser.Parse(bytearray);
                    xmlstring = parsed.ToXmlPropertyList();
                }
                else
                {
                    xmlstring = Encoding.UTF8.GetString(bytearray);
                }
                return XDocument.Parse(new string(xmlstring.Where(ch => XmlConvert.IsXmlChar(ch)).ToArray()));
            }
            catch (Exception e)
            {
                HelperMethods.OutputMessage($"[ERROR] Failed to parse plist to XDocument: {e}");
                return new XDocument();
            }
        }

        private static string GetPlistValue(XDocument doc, string key)
        {
            XElement plist = doc.Element("plist");
            foreach (XElement dict in plist.Descendants("dict"))
            {
                var elements = dict.Elements();
                try
                {
                    return ((XElement)elements.FirstOrDefault(e => e.Value == key).NextNode).Value;
                }
                catch { }
            }
            return "unknown";
        }

        /// <summary>
        /// Use Regripper to get users info.
        /// Input: temp file created with data from reg file.
        /// </summary>
        public static int Regripper()
        {
            HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: Getting SAM info...");
            string[] oe = StartProcess("powershell.exe",
                $"& \'{AppDomain.CurrentDomain.BaseDirectory}XTensions\\Tools\\RegRipper\\rip.exe\' -r \'{CaseInfo_XT.sam_filename}\' -f sam");

            if (oe[0] == "")
            {
                if (oe[1].Contains("CommandNotFoundException")) HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: " +
                    $"[ERROR] Please check if RegRipper is in the Tools directory!");
                else if (oe[1].ToLower().Contains("no key account")) HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: " +
                    $"[ERROR] Please exclude any SAM registry file that is incomplete/incorrect and run RVS without the excluded files");
                else HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: [ERROR] Powershell error message:\n{oe[1]}");
                return -1;
            }

            string reguserinfo = Get_split(oe[0], "-------------------------\r\n")[1];
            string[] regusers = Get_split(reguserinfo, "\r\n\r\n");
            ProcessUsersNew(regusers.Take(regusers.Length - 1).ToArray());

            return 0;
        }

        /// <summary>
        /// Use impacket to get domain users and their hashes
        /// </summary>
        public static int Impacket(bool forDomain)
        {
            HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: Getting hashes (and domain users)...");

            //string cmd = $"& secretsdump.py -sam \'{CaseInfo_XT.sam_filename}\' -system \'{CaseInfo_XT.system_filename}\' LOCAL";
            string cmd = $"& py \'{AppDomain.CurrentDomain.BaseDirectory}XTensions\\Tools\\impacket\\examples\\secretsdump.py\' " +
                $"-sam \'{CaseInfo_XT.sam_filename}\' -system \'{CaseInfo_XT.system_filename}\' LOCAL";
            if (forDomain) cmd += $" -security \'{CaseInfo_XT.security_filename}\'";
            string[] oe = StartProcess("powershell.exe", cmd);

            if (oe[0] == "")
            {
                if (oe[1] != null) HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: [ERROR] Powershell error message:\n{oe[1]}");
                else HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: [ERROR] Unknown error executing Impacket");
                return -1;
            }
            
            string[] blocks = Get_split(oe[0], "\r\n[*] ");

            string local_s = Array.Find(blocks, element => element.Contains("Dumping local SAM hashes"));
            string[] local = Get_split(local_s, "\r\n");
            ProcessUsersNTLM(local.Skip(1).Take(local.Length - 1).ToArray());

            if (forDomain)
            {
                string domain_s = Array.Find(blocks, element => element.Contains("Dumping cached domain logon information"));
                string[] domain = Get_split(domain_s, "\r\n");
                ProcessUsersDomain(domain.Skip(1).Take(local.Length - 1).ToArray());
            }
            
            return 0;
        }

        private static string GetMacHash(IntPtr hItem)
        {
            HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: Getting hash for user...");

            // create temp plist file
            string plist_filename = Path.GetTempFileName();
            System.IO.File.Move(plist_filename, Path.ChangeExtension(plist_filename, ".plist"));
            plist_filename = Path.ChangeExtension(plist_filename, ".plist");
            FileInfo fi = new FileInfo(plist_filename);
            fi.Attributes = FileAttributes.Temporary;

            // add data to temp plist file
            byte[] item_file = HelperMethods.ReadItem(hItem);
            System.IO.File.WriteAllBytes(plist_filename, item_file);

            // create temp file for script output
            string output_filename = Path.GetTempFileName();
            System.IO.File.Move(output_filename, Path.ChangeExtension(output_filename, ".txt"));
            output_filename = Path.ChangeExtension(output_filename, ".txt");
            FileInfo fi2 = new FileInfo(output_filename);
            fi2.Attributes = FileAttributes.Temporary;

            string cmd = $"& py \'{AppDomain.CurrentDomain.BaseDirectory}XTensions\\Tools\\machash.py\' " +
                $"\"{plist_filename}\" \"{output_filename}\"";
            string[] oe = StartProcess("powershell.exe", cmd);

            if (oe[1].Contains("CommandNotFoundException"))
            {
                HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: [ERROR] Please check if machash is in the Tools directory!\n" +
                    $"OS X version might be <10.8");
                return "unknown";
            }

            string[] output = System.IO.File.ReadAllLines(output_filename);
            var hash = Get_split(output[0], ":")[1];

            //Delete temp files
            System.IO.File.Delete(plist_filename);
            System.IO.File.Delete(output_filename);

            return hash;
        }

        public static string ChooseLanguage()
        {
            var lang = HelperMethods.GetUserInput("Run ReportAutomator at the end? Cancel to not run", "Report language NL or FR");
            switch (lang.ToUpper())
            {
                case "NL":
                    choice = "NL";
                    break;
                case "FR":
                    choice = "FR";
                    break;
                case "CLICKED CANCEL":
                    choice = "cancel";
                    break;
                default:
                    ChooseLanguage();
                    break;
            }
            return choice;
        }

        public static bool ReportAutomator(string json, string lang, string filename)
        {
            HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: Generating report from results with ReportAutomator...");

            string cmd = $"& Set-Location -Path \'{AppDomain.CurrentDomain.BaseDirectory}XTensions\\Tools\\ReportAutomator\\\'; " +
                $"py \'ReportAutomator.py\' string \'{json.Replace("\"", "\\\"\\\"")}\' {lang} \'{filename}_report\'";
            string[] oe = StartProcess("powershell.exe", cmd);

            if (oe[0].Contains("ERROR")) return false;
            if (oe[0].Contains("Saved")) return true;

            return false;
        }
        
        /// <summary>
        /// Create a new process to execute a powershell command.
        /// </summary>
        /// <param name="exe">Powershell exe</param>
        /// <param name="cmd">Command to be executed by 'exe' parameter.</param>
        /// <returns>Returns output and error output from command.</returns>
        private static string[] StartProcess(string exe, string cmd)
        {
            Process p = new Process();
            p.StartInfo.UseShellExecute = false;
            p.StartInfo.RedirectStandardOutput = true;
            p.StartInfo.RedirectStandardError = true;
            p.StartInfo.FileName = exe;
            p.StartInfo.Arguments = cmd;
            p.StartInfo.CreateNoWindow = true;
            if (cmd.Contains("RegRipper"))
            {
                p.StartInfo.StandardOutputEncoding = Encoding.UTF8;
                p.StartInfo.StandardErrorEncoding = Encoding.UTF8;
            }
            p.Start();
            string output = p.StandardOutput.ReadToEnd();
            string error = p.StandardError.ReadToEnd();
            p.WaitForExit();

            return new string[] { output, error };
        }

        public static string[] Get_split(string el, string del)
        {
            return el.Split(new string[] { del }, StringSplitOptions.None);
        }

        private static string Get_prop(string[] userinfo, string prop)
        {
            var el = Array.Find(userinfo, element => element.Contains(prop));
            var result = string.IsNullOrEmpty(el) ? "unknown" : Get_split(el, ": ")[1];
            return string.IsNullOrEmpty(result) ? "unknown" : result;
        }

        /// <summary>
        /// Add a new user
        /// </summary>
        /// <param name="users"></param>
        private static void ProcessUsersNew(string[] users)
        {
            foreach (string u in users)
            {
                string[] userinfo = Get_split(u, "\r\n");

                string sid = Get_prop(userinfo, "SID");
                string username = Get_split(Get_prop(userinfo, "Username"), " [")[0];
                string fullname = Get_prop(userinfo, "Full Name");
                string internetName = Get_prop(userinfo, "InternetName");
                string comment = Get_prop(userinfo, "User Comment");
                string lastlogin = Get_prop(userinfo, "Last Login Date");
                string pwdHint = Get_prop(userinfo, "Password Hint");
                bool isInactive = (Array.Find(userinfo, element => element.Contains("Account Disabled")) != null);

                // add user to specific partition
                if (CaseInfo_XT.current_part != null)
                {
                    CaseInfo_XT.current_part.Users.Add(new User(sid, username, fullname, internetName, comment, lastlogin, pwdHint, isInactive));
                }
                else
                {
                    HelperMethods.OutputMessage($"The user's partition could not be found. User {username} will be added to case.");
                    CaseInfo_XT.caseusers = true;
                    CaseInfo_XT.current_case.Users.Add(new User(sid, username, fullname, internetName, comment, lastlogin, pwdHint, isInactive));
                }
            }
        }

        private static void ProcessUsersDomain(string[] users)
        {
            foreach (string u in users)
            {
                string domain = Get_split(u, "/")[0];
                string username = Get_split(Get_split(u, "/")[1], ":")[0];
                string hash = Get_split(u, ":")[1];

                // add user to specific partition
                if (CaseInfo_XT.current_part != null)
                {
                    CaseInfo_XT.current_part.Users.Add(new User("unknown", username, hash, Get_split(u, "$")[1], domain));
                }
                else
                {
                    HelperMethods.OutputMessage($"The user's partition could not be found. User {username} will be added to case.");
                    CaseInfo_XT.caseusers = true;
                    CaseInfo_XT.current_case.Users.Add(new User("unknown", username, hash, Get_split(u, "$")[1], domain));
                }
            }
        }

        /// <summary>
        /// Add NTLM hash to existing user (or new user if user not found)
        /// </summary>
        private static void ProcessUsersNTLM(string[] users)
        {
            foreach (string u in users)
            {
                string username = Get_split(u, ":")[0];
                try
                {
                    string ntlm = Get_split(u, ":")[3];
                    User current_user = User.GetUser(username);

                    if (current_user != null)
                    {
                        current_user.Hash = ntlm;
                        current_user.HashType = "NTLM";
                    }
                    else
                    {
                        HelperMethods.OutputMessage($"User {username} not found in case. The new user will be added to the case.");
                        CaseInfo_XT.current_case.Users.Add(new User(Get_split(u, ":")[1], username, ntlm, "NTLM"));
                    }
                }
                catch
                {
                    HelperMethods.OutputMessage($"No NTLM hash found for user {username}");
                }
            }
        }

        public static int ProcessAsl()
        {
            var asl_file = CaseInfo_XT.asl_files[CaseInfo_XT.asl_dates.IndexOf(CaseInfo_XT.asl_dates.Max())];

            string output = Path.GetTempFileName();
            FileInfo fi = new FileInfo(output);
            fi.Attributes = FileAttributes.Temporary;

            HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: Getting ASL info...");
            string cmd = $"& py \'{AppDomain.CurrentDomain.BaseDirectory}XTensions\\Tools\\ccl-asl\\ccl_asldb.py\' " +
                $"-i file {asl_file} -o {output} -t tsv";
            string[] oe = StartProcess("powershell.exe", cmd);
            if (oe[1] != "")
            {
                HelperMethods.OutputMessage($"{DateTime.Now.TimeOfDay}: [ERROR] Powershell error message:\n{oe[1]}");
                return -1;
            }

            var asl_list = new List<string>(System.IO.File.ReadAllLines(output));
            asl_list.Reverse();

            string pattern = "yyyy-MM-dd";

            var shutdown = asl_list.FirstOrDefault(l => l.Contains("shutdown")) ?? "unknown";
            if (shutdown != "unknown")
            {
                var shut_date = Get_split(Get_split(shutdown, "\t")[0], "T")[0];
                DateTime.TryParseExact(shut_date, pattern, null, DateTimeStyles.None, out DateTime t_out);
                CaseInfo_XT.current_part.Shutdown = t_out.ToString("dd/MM/yyyy");
            }

            var logins = asl_list.Where(l => l.Contains("login") && !l.Contains("window"));
            if (logins.Count() != 0)
            {
                foreach (User u in CaseInfo_XT.current_part.Users)
                {
                    var login = logins.FirstOrDefault(l => l.Contains(u.Username)) ?? "unknown";
                    if (login != "unknown")
                    {
                        var login_date = Get_split(Get_split(login, "\t")[0], "T")[0];
                        DateTime.TryParseExact(login_date, pattern, null, DateTimeStyles.None, out DateTime t_out);
                        u.LastLogin = t_out.ToString("dd/MM/yyyy");
                    }
                }
            }

            System.IO.File.Delete(output);
            foreach (string f in CaseInfo_XT.asl_files) System.IO.File.Delete(f);

            return 0;
        }

        
        private static string SetVolumeRegex(IntPtr hItem)
        {
            var path_part = Get_split(HelperMethods.GetProp(hItem).Path, "\\");
            var mac_ctr = @"^\\" + path_part[1];
            if (!CaseInfo_XT.hasvols && path_part[2].Contains(" - "))
            {
                CaseInfo_XT.hasvols = true;
                CaseInfo_XT.prefix_systemversion = @"\\[^\\]+";
                CaseInfo_XT.prefix = @"\\[^\\]+-[^\\]+";
            }
            return mac_ctr;
        }

    }
}
