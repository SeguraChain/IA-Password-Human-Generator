using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IA_Password_Human_Generator.Object
{
    /// <summary>
    /// IA object containing data from the scanned passwords report.
    /// </summary>
    public class IAPasswordData
    {
        public SortedDictionary<char, decimal> PasswordCharacterRank = new SortedDictionary<char, decimal>();
        public SortedDictionary<decimal, decimal> PasswordLengthRank = new SortedDictionary<decimal, decimal>();
        public SortedDictionary<decimal, SortedDictionary<char, decimal>> PasswordPosRank = new SortedDictionary<decimal, SortedDictionary<char, decimal>>();
        public long TotalPassword;
    }

    /// <summary>
    /// Used to contain lists of passwords generated from a report IA passwords previously generated.
    /// </summary>
    public class FileStreamObject
    {
        public string NameFile;
        public FileStream FileStreamReader;
        public FileStream FileStreamWriter;
        public StreamWriter StreamWriter;
        public StreamReader StreamReader;
        public long Total;
        public HashSet<string> ListWord;

        /// <summary>
        /// Constructor.
        /// </summary>
        public FileStreamObject()
        {
            ListWord = new HashSet<string>();
        }
    }

    /// <summary>
    /// Used to sort passwords from a file.
    /// </summary>
    public class StreamWriterObject
    {
        public FileStream FileStreamReader;
        public FileStream FileStreamWriter;
        public StreamWriter StreamWriter;
        public StreamReader StreamReader;
        public int Total;
    }
}
