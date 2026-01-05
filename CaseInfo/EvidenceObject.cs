using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Reflection;
using XTensions;

namespace CaseInfo
{
    public class Case
    {
        [JsonProperty(Order = 1)]
        public string Title { get; set; }
        [JsonProperty(Order = 2)]
        public List<Disk> Disks = new List<Disk>();
        [JsonProperty(Order = 3)]
        public List<Partition> Partitions = new List<Partition>();
        [JsonProperty(Order = 4)]
        public int NoUsers { get => Users.Count; set => NoUsers = value; }
        [JsonProperty(Order = 5)]
        public List<User> Users = new List<User>();
        [JsonProperty(Order = 6)]
        public General General = new General();

        public Case(string title) {
            this.Title = title;
        }
    }

    public class Disk
    {
        [JsonProperty(Order = 1)]
        public string Name { get; set; }
        [JsonIgnore]
        public EvidenceObjectProperties Properties;
        [JsonProperty(Order = 2)]
        public string Size { get; set; }
        [JsonProperty(Order = 3)]
        public List<Partition> Partitions = new List<Partition>();

        public Disk(EvidenceObjectProperties properties)
        {
            this.Properties = properties;
            this.Name = Properties.title;
            var descr_array = Properties.description.Split(new string[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
            this.Size = Partition.Get_split(Array.Find(descr_array, element => element.Contains("Total capacity:")), " = ");
        }

    }

    public class Partition
    {
        [JsonProperty(Order = 1)]
        public string Name { get; set; }
        [JsonProperty(Order = 2)]
        public string Label { get; set; }
        [JsonProperty(Order = 3)]
        public string Type { get; set; }
        [JsonProperty(Order = 4)]
        public string Size { get; set; }
        [JsonProperty(Order = 5)]
        public string Free { get; set; }
        [JsonProperty(Order = 6)]
        public string FirstSector { get; set; }
        [JsonProperty(Order = 7)]
        public string OS { get; set; }
        [JsonProperty(Order = 8)]
        public string ComputerName { get; set; }
        [JsonProperty(Order = 9)]
        public string Timezone { get; set; }
        [JsonProperty(Order = 10)]
        public string Installation { get; set; }
        [JsonProperty(Order = 11)]
        public string Shutdown { get; set; }
        [JsonProperty(Order = 12)]
        public string LabelDate { get; set; }
        [JsonProperty(Order = 13)]
        public string Owner { get; set; }
        [JsonProperty(Order = 14)]
        public int NoUsers { get => Users.Count; set => NoUsers = value; }
        [JsonProperty(Order = 15)]
        public List<User> Users = new List<User>();
        [JsonProperty(Order = 16)]
        public List<Volume> Volumes = new List<Volume>();

        public Partition(EvidenceObjectProperties properties)
        {
            this.Name = properties.title;
            this.Type = (properties.FileSystemIdentifier.ToString() == "HFSPlus") ? "HFS+" : properties.FileSystemIdentifier.ToString();
            if (this.Name == "hiberfil.sys") this.Type = "hiberfil.sys";
            
            var descr_array = properties.description.Split(new string[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);

            this.Label = Get_split(Array.Find(descr_array, element => element.Contains("Name:")));
            this.Free = Get_split(Array.Find(descr_array, element => element.Contains("Free clusters:")), " = ").Split(' ')[0];

            if (properties.description.Contains("XWFS")) this.Size = Get_split(Array.Find(descr_array, element => element.Contains("Total capacity:")), ": ");
            else this.Size = Get_split(Array.Find(descr_array, element => element.Contains("Total capacity:")), " = ");
            
            this.OS = Get_split(Array.Find(descr_array, element => element.Contains("Version:")));
            if (this.OS == "" && descr_array[0].Contains("Windows")) this.OS = "Windows";
            else if (this.OS == "unknown" && descr_array[0].Contains("XWFS")) this.OS = "MacOS";

            this.ComputerName = Get_split(Array.Find(descr_array, element => element.Contains("Computer name:")));
            this.Owner = Get_split(Array.Find(descr_array, element => element.Contains("Owner:")));
            this.Timezone = Get_split(Array.Find(descr_array, element => element.Contains("Time zone:")));

            this.Installation = Get_split(Array.Find(descr_array, element => element.Contains("Installation:")));
            if (!String.Equals(this.Installation, "unknown")) this.Installation = Transform_date(this.Installation);
            this.Shutdown = Get_split(Array.Find(descr_array, element => element.Contains("Last shutdown:")));
            if (!String.Equals(this.Shutdown, "unknown")) this.Shutdown = Transform_date(this.Shutdown);

            this.LabelDate = Get_split(Array.Find(descr_array, element => element.Contains("Volume label date:")));
            if (!String.Equals(this.Shutdown, "unknown")) this.Shutdown = Transform_date(this.Shutdown);

            this.FirstSector = "unknown";

            // volumes (macos)
            if (this.Type == "APFS" || this.Type == "HFS+")
            {
                var volumes = properties.description.Split(new string[] { "\r\n\r\n\r\n" }, StringSplitOptions.None).Skip(1);
                foreach (string v in volumes)
                {
                    if(v.StartsWith("Volume")) Volumes.Add(new Volume(v));
                }
            }
        }

        public static string Get_split(string el, string del = ": ")
        {
            return (el == null) ? "unknown" : el.Split(new string[] { del }, StringSplitOptions.None)[1];
        }

        public static string Transform_date(string timestamp)
        {
            if (!String.Equals(timestamp, "Never")) return timestamp.Split(new string[] { "  " }, StringSplitOptions.None)[0];
            else return timestamp;
        }

        /// <summary>
        /// Get the partition currently being processed
        /// </summary>
        public static Partition GetPartition(IntPtr _hEvidence)
        {
            string partname_long = HelperMethods.GetEvidenceObjectProperties(_hEvidence).extendedTitle;
            string partname = "";
            Disk disk = null;
            string[] name_split = CaseInfo_Methods.Get_split(partname_long, ", ");
            if (name_split.Length == 1)
            {
                partname = CaseInfo_Methods.Get_split(partname_long, ", ")[0];
            }
            else
            {
                string diskname = CaseInfo_Methods.Get_split(partname_long, ", ")[0];
                partname = CaseInfo_Methods.Get_split(partname_long, ", ")[1];
                disk = CaseInfo_XT.current_case.Disks.Find(e => e.Name.Equals(diskname));
            }
            return (disk != null) ? disk.Partitions.Find(e => e.Name.Equals(partname)) :
                CaseInfo_XT.current_case.Partitions.Find(e => e.Name.Equals(partname));
        }
    }

    public class Volume
    {
        [JsonProperty(Order = 1)]
        public string Label { get; set; }
        /*[JsonProperty(Order = 2)]
        public string Size { get; set; }*/
        [JsonProperty(Order = 3)]
        public string Creation { get; set; }
        [JsonProperty(Order = 4)]
        public string LastWrite { get; set; }

        public Volume(string v)
        {
            var descr_array = v.Split(new string[] { "\r\n", "\r", "\n" }, StringSplitOptions.None);
            this.Label = Get_volume_split(Array.Find(descr_array, element => element.Contains("Label")), ": ");
            this.Creation = Get_volume_split(Array.Find(descr_array, element => element.Contains("Creation")), ": ")
                .Split(new string[] { "  " }, StringSplitOptions.None)[0];
            this.LastWrite = Get_volume_split(Array.Find(descr_array, element => element.Contains("Last Write")), ": ")
                .Split(new string[] { "  " }, StringSplitOptions.None)[0];
        }

        public static string Get_volume_split(string el, string del = ": ")
        {
            return (el == null) ? "unknown" : CaseInfo_Methods.Get_split(el, del)[1];
        }

    }

    public class User
    {
        public string Domain { get; set; }
        [JsonProperty(Order = 1)]
        public string SID { get; set; }
        [JsonProperty(Order = 2)]
        public string Username { get; set; }
        [JsonProperty(Order = 3)]
        public string FullName { get; set; }
        [JsonProperty(Order = 4)]
        public string InternetName { get; set; }
        [JsonProperty(Order = 5)]
        public string Comment { get; set; }
        [JsonProperty(Order = 6)]
        public string LastLogin { get; set; }
        [JsonProperty(Order = 7)]
        public string Hash { get; set; }
        [JsonProperty(Order = 8)]
        public string HashType { get; set; }
        [JsonProperty(Order = 9)]
        public string PwdHint { get; set; }
        [JsonProperty(Order = 10)]
        public bool IsInactive { get; set; }

        public User(string username) : 
            this("local", "unknown", username, "unknown", "unknown", "unknown", "unknown", "unknown", "unknown", "unknown", false)
        {
            /*
            SID = "unknown";
            Hash = "unknown";
            HashType = "unknown";
            Domain = "local";
            FullName = "unknown";
            InternetName = "unknown";
            Comment = "unknown";
            LastLogin = "unknown";
            PwdHint = "unknown";
            IsInactive = false;
            */

            this.Username = username;
        }

        public User(string username, string hash, string hashtype) : 
            this("local", "unknown", username, "unknown", "unknown", "unknown", "unknown", hash, hashtype, "unknown", false)
        {
            /*
            SID = "unknown";
            Domain = "local";
            FullName = "unknown";
            InternetName = "unknown";
            Comment = "unknown";
            LastLogin = "unknown";
            PwdHint = "unknown";
            IsInactive = false;
            */

            this.Username = username;
            this.Hash = hash;
            this.HashType = hashtype;
        }

        public User(string sid, string username, string full, string hash, string hashtype, string pwdHint) : 
            this("local", sid, username, full, "unknown", "unknown", "unknown", hash, hashtype, pwdHint, false)
        {
            /*
            Internetname = "unknown";
            Comment = "unknown";
            Domain = "local";
            IsInactive = false;
            LastLogin = "unknown";
            */

            this.SID = sid;
            this.Username = username;
            this.Hash = hash;
            this.HashType = hashtype;
            this.FullName = full;
            this.PwdHint = pwdHint;
        }

        public User(string sid, string username, string hash, string hashtype, string domain = "local", bool isInactive = false) : 
            this(domain, sid, username, "unknown", "unknown", "unknown", "unknown", hash, hashtype, "unknown", isInactive)
        {
            /*
            FullName = "unknown";
            InternetName = "unknown";
            Comment = "unknown";
            LastLogin = "unknown";
            PwdHint = "unknown";
            IsInactive = isInactive;
            */

            this.SID = sid;
            this.Username = username;
            this.Hash = hash;
            this.HashType = hashtype;
            this.Domain = domain;
            this.IsInactive = isInactive;
        }

        public User(string sid, string username, string full, string internetName, string comment, string last, string pwdHint, bool isInactive, string domain = "local") : 
            this(domain, sid, username, full, internetName, comment, last, "unknown", "unknown", pwdHint, isInactive)
        {
            /*
            Hash = "unknown";
            HashType = "unknown";
            */

            this.SID = sid;
            this.Username = username;
            this.Domain = domain;
            this.FullName = full;
            this.InternetName = internetName;
            this.Comment = comment;
            this.PwdHint = pwdHint;
            this.IsInactive = isInactive;

            if (String.Equals(last, "Never"))
            {
                this.LastLogin = last;
            } else
            {
                string[] date = last.Replace("  ", " 0").Split(new string[] { " " }, StringSplitOptions.None).Skip(1).Take(4).ToArray();
                string login = string.Join(" ", date);
                string pattern = "MMM dd HH:mm:ss yyyy";
                DateTime.TryParseExact(login, pattern, null, DateTimeStyles.None, out DateTime output);
                this.LastLogin = output.ToString("dd/MM/yyyy");
            }
        }

        private User(string domain, string sID, string username, string fullName, string internetName, string comment, string lastLogin, string hash, string hashType, string pwdHint, bool isInactive)
        {
            this.SID = sID;
            this.Username = username;
            this.Hash = hash;
            this.HashType = hashType;
            this.Domain = domain;
            this.FullName = fullName;
            this.InternetName = internetName;
            this.Comment = comment;
            this.LastLogin = lastLogin;
            this.PwdHint = pwdHint;
            this.IsInactive = isInactive;
        }
        public static User GetUser(string username)
        {
            return (!CaseInfo_XT.caseusers) ? CaseInfo_XT.current_part.Users.Find(e => e.Username.Equals(username)) :
                CaseInfo_XT.current_case.Users.Find(e => e.Username.Equals(username));
        }
    }

    public class General
    {
        [JsonProperty(Order = 1)]
        public string XWaysVersion { get; set; }
        [JsonProperty(Order = 2)]
        public string DllVersion { get; set; }

        public General() {
            var app = AppDomain.CurrentDomain;

            this.XWaysVersion = FileVersionInfo.GetVersionInfo(
                $"{app.SetupInformation.ApplicationBase}{app.SetupInformation.ApplicationName}").ProductVersion;

            Assembly a = Array.Find(app.GetAssemblies(), el => el.FullName.Contains("CaseInfo"));
            this.DllVersion = a.FullName.Split(new string[] { ", " }, StringSplitOptions.None)[1]
                .Split(new string[] { "=" }, StringSplitOptions.None)[1];
        }

        

    }

}