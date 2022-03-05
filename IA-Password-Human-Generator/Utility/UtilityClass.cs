using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace IA_Password_Human_Generator.Utility
{
    public class UtilityClass
    {
        /// <summary>
        ///  Generate a random long number object between a range selected.
        /// </summary>
        /// <param name="minimumValue"></param>
        /// <param name="maximumValue"></param>
        /// <returns></returns>
        public static decimal GetRandomBetween(decimal minimumValue, decimal maximumValue)
        {
            using (RNGCryptoServiceProvider generator = new RNGCryptoServiceProvider())
            {
                var randomNumber = new byte[sizeof(float)];

                generator.GetBytes(randomNumber);

                var asciiValueOfRandomCharacter = Convert.ToDouble(randomNumber[0]);

                var multiplier = Math.Max(0, asciiValueOfRandomCharacter / 255d - 0.00000000001d);

                var range = maximumValue - minimumValue + 1;

                var randomValueInRange = Math.Floor(multiplier * (double)range);

                return (minimumValue + (decimal)randomValueInRange);
            }
        }

        /// <summary>
        /// Get a string from a hex string and choose the right Encoding class to return this one propertly.
        /// </summary>
        /// <param name="hexBytes"></param>
        /// <returns></returns>
        private static string GetStringFromByteArrayHexString(byte[] hexBytes)
        {
            string line;
            hexBytes = hexBytes.TakeWhile((v, index) => hexBytes.Skip(index).Any(w => w != 0x00)).ToArray();

            var encoding = new TextEncodingDetect().DetectEncoding(hexBytes, hexBytes.Length);

            switch (encoding)
            {
                case TextEncodingDetect.Encoding.Ansi:
                    line = Encoding.GetEncoding(1252).GetString(hexBytes);
                    break;
                case TextEncodingDetect.Encoding.Ascii:
                    line = Encoding.ASCII.GetString(hexBytes);
                    break;
                case TextEncodingDetect.Encoding.Utf16BeBom:
                    {
                        var encode = new UnicodeEncoding(true, true, false);
                        line = encode.GetString(hexBytes);
                    }
                    break;
                case TextEncodingDetect.Encoding.Utf16BeNoBom:
                    {
                        try
                        {
                            var encode = new UnicodeEncoding(true, false, true);
                            line = encode.GetString(hexBytes);
                        }
                        catch
                        {
                            try
                            {
                                var encode = new UnicodeEncoding(true, true, true);
                                line = encode.GetString(hexBytes);
                            }
                            catch
                            {
                                try
                                {
                                    line = Encoding.GetEncoding("gb2312").GetString(hexBytes);
                                }
                                catch
                                {
                                    line = Encoding.GetEncoding(1252).GetString(hexBytes);
                                }
                            }
                        }
                    }
                    break;

                case TextEncodingDetect.Encoding.Utf16LeBom:
                    {
                        var encode = new UnicodeEncoding(false, true, false);
                        line = encode.GetString(hexBytes);
                    }
                    break;
                case TextEncodingDetect.Encoding.Utf16LeNoBom:
                    {
                        try
                        {
                            var encode = new UnicodeEncoding(false, false, true);
                            line = encode.GetString(hexBytes);
                        }
                        catch
                        {
                            try
                            {
                                var encode = new UnicodeEncoding(false, true, true);
                                line = encode.GetString(hexBytes);
                            }
                            catch
                            {
                                try
                                {
                                    line = Encoding.GetEncoding("gb2312").GetString(hexBytes);
                                }
                                catch
                                {
                                    line = Encoding.GetEncoding(1252).GetString(hexBytes);
                                }
                            }
                        }
                    }
                    break;
                case TextEncodingDetect.Encoding.Utf8Bom:
                    {
                        var encode = new UTF8Encoding(true);
                        line = encode.GetString(hexBytes);
                    }
                    break;
                case TextEncodingDetect.Encoding.Utf8Nobom:
                    {
                        var encode = new UTF8Encoding(false);
                        line = encode.GetString(hexBytes);
                    }
                    break;
                default:
                    line = Encoding.UTF8.GetString(hexBytes);
                    break;
            }

            line = new string(line.Where(c => !char.IsControl(c)).ToArray());
            line = RemoveControlCharacter(line);

            return line;
        }

        /// <summary>
        /// Split password from an email.
        /// </summary>
        /// <param name="line"></param>
        /// <param name="characterSeperator"></param>
        /// <param name="newLine"></param>
        /// <param name="ignoreHex"></param>
        /// <param name="converted"></param>
        /// <returns></returns>
        public static bool SplitMergedPassFromEmail(string line, string characterSeperator, out string newLine, out bool ignoreHex, out bool converted)
        {
            ignoreHex = false;
            converted = false;
            if (line.Contains(characterSeperator))
            {

                if (line.Count(x => x == characterSeperator[0]) == 1)
                {
                    string[] lineSplit = line.Split(new[] { characterSeperator }, StringSplitOptions.None);
                    if (RegexEmail.IsMatch(lineSplit[0]) || (lineSplit[0].Contains("@") && lineSplit[0].Contains(".")))
                    {
                        newLine = lineSplit[1];
                        if (RegexHex.IsMatch(newLine) && newLine.Length >= 32)
                        {
                            bool containLetter = false;

                            foreach (var character in newLine)
                            {
                                if (char.IsLetter(character))
                                {
                                    containLetter = true;
                                    break;
                                }
                            }

                            if (containLetter)
                            {
                                ignoreHex = true;
                                return false;
                            }
                        }

                        if (newLine.Contains("$HEX[") || newLine.Contains("$hex["))
                        {
                            newLine = newLine.Replace("$HEX[", "");
                            newLine = newLine.Replace("$hex[", "");
                            newLine = newLine.Replace("]", "");
                            var hexBytes = GetByteArrayFromHexString(newLine);
                            if (hexBytes != null)
                            {
                                newLine = GetStringFromByteArrayHexString(hexBytes);
                                converted = true;
                                //Debug.WriteLine(lineSplit[1] + " -> " + newLine);
                            }
                            else
                            {
                                ignoreHex = true;
                                return false;
                            }
                        }

                        if (newLine.Contains(" | "))
                        {
                            int indexOf = newLine.IndexOf(" | ");
                            var newLineTest = newLine.Substring(0, indexOf);

                            newLine = newLineTest;
                            converted = true;
                        }

                        if (RegexEmail.IsMatch(newLine))
                        {
                            if (newLine.Contains(characterSeperator))
                            {
                                var splitNewLine = newLine.Split(new[] { characterSeperator }, StringSplitOptions.None);
                                if (splitNewLine.Length > 1)
                                {
                                    if (!string.IsNullOrEmpty(splitNewLine[1]))
                                    {
                                        if (splitNewLine[1].Length > 4)
                                        {
                                            if (!RegexEmail.IsMatch(splitNewLine[1]) && !RegexHex.IsMatch(splitNewLine[1]))
                                            {
                                                newLine = splitNewLine[1];
                                                return true;
                                            }
                                        }
                                    }
                                }
                            }
                            ignoreHex = true;
                            return false;

                        }

                        return true;
                    }

                    long timestamp = DateTimeOffset.Now.ToUnixTimeSeconds();

                    string email = string.Empty;
                    string pass = string.Empty;

                    bool spaceFound = false;
                    foreach (var lineCaracter in line)
                    {
                        if (!spaceFound)
                        {
                            if (lineCaracter == characterSeperator[0])
                                spaceFound = true;
                            else
                                email += lineCaracter;
                        }
                        else
                            pass += lineCaracter;

                        if (timestamp + 5 < DateTimeOffset.Now.ToUnixTimeSeconds())
                        {
                            Debug.WriteLine("Error stuck on splitting line: " + line);
                            break;
                        }
                    }


                    if (RegexEmail.IsMatch(email))
                    {
                        if (RegexHex.IsMatch(pass) && pass.Length >= 32)
                        {
                            bool containLetter = false;

                            foreach (var character in pass)
                            {
                                if (char.IsLetter(character))
                                {
                                    containLetter = true;
                                    break;
                                }
                            }

                            if (containLetter)
                                ignoreHex = true;
                        }
                        else
                        {
                            newLine = pass;

                            if (newLine.Contains("$HEX[") || newLine.Contains("$hex["))
                            {
                                newLine = newLine.Replace("$HEX[", "");
                                newLine = newLine.Replace("$hex[", "");
                                newLine = newLine.Replace("]", "");
                                var hexBytes = GetByteArrayFromHexString(newLine);
                                if (hexBytes != null)
                                {
                                    newLine = GetStringFromByteArrayHexString(hexBytes);
                                    converted = true;
                                }
                                else
                                {
                                    ignoreHex = true;
                                    return false;
                                }
                            }

                            if (newLine.Contains(" | "))
                            {
                                int indexOf = newLine.IndexOf(" | ");
                                var newLineTest = newLine.Substring(0, indexOf);

                                newLine = newLineTest;
                                converted = true;
                            }

                            if (RegexEmail.IsMatch(newLine))
                            {
                                if (newLine.Contains(characterSeperator))
                                {
                                    var splitNewLine = newLine.Split(new[] { characterSeperator }, StringSplitOptions.None);
                                    if (splitNewLine.Length > 1)
                                    {
                                        if (!string.IsNullOrEmpty(splitNewLine[1]))
                                        {
                                            if (splitNewLine[1].Length > 4)
                                            {
                                                if (!RegexEmail.IsMatch(splitNewLine[1]) && !RegexHex.IsMatch(splitNewLine[1]))
                                                {
                                                    newLine = splitNewLine[1];
                                                    return true;
                                                }
                                            }
                                        }
                                    }
                                }
                                ignoreHex = true;
                                return false;

                            }

                            return true;

                        }
                    }
                }
                else
                {
                    string email = string.Empty;
                    string pass = string.Empty;
                    long timestamp = DateTimeOffset.Now.ToUnixTimeSeconds();

                    bool spaceFound = false;
                    foreach (var lineCaracter in line)
                    {
                        if (!spaceFound)
                        {
                            if (lineCaracter == characterSeperator[0])
                                spaceFound = true;
                            else
                                email += lineCaracter;
                        }
                        else
                            pass += lineCaracter;

                        if (timestamp + 5 < DateTimeOffset.Now.ToUnixTimeSeconds())
                        {
                            Debug.WriteLine("Error stuck on splitting line: " + line);
                            break;
                        }
                    }


                    if (RegexEmail.IsMatch(email) || (email.Contains("@") && email.Contains(".")))
                    {
                        if ((RegexHex.IsMatch(pass) && pass.Length >= 32) || pass.Length >= 32)
                        {
                            bool containLetter = false;

                            foreach (var character in pass)
                            {
                                if (char.IsLetter(character))
                                {
                                    containLetter = true;
                                    break;
                                }
                            }

                            if (containLetter)
                                ignoreHex = true;

                        }
                        else
                        {
                            newLine = pass;

                            if (newLine.Contains("$HEX[") || newLine.Contains("$hex["))
                            {
                                newLine = newLine.Replace("$HEX[", "");
                                newLine = newLine.Replace("$hex[", "");
                                newLine = newLine.Replace("]", "");
                                var hexBytes = GetByteArrayFromHexString(newLine);
                                if (hexBytes != null)
                                {
                                    newLine = GetStringFromByteArrayHexString(hexBytes);
                                    converted = true;
                                }
                                else
                                {
                                    ignoreHex = true;
                                    return false;
                                }
                            }

                            if (newLine.Contains(" | "))
                            {
                                int indexOf = newLine.IndexOf(" | ");
                                var newLineTest = newLine.Substring(0, indexOf);

                                newLine = newLineTest;
                                converted = true;
                            }

                            if (RegexEmail.IsMatch(newLine))
                            {
                                if (newLine.Contains(characterSeperator))
                                {
                                    var splitNewLine = newLine.Split(new[] { characterSeperator }, StringSplitOptions.None);
                                    if (splitNewLine.Length > 1)
                                    {
                                        if (!string.IsNullOrEmpty(splitNewLine[1]))
                                        {
                                            if (splitNewLine[1].Length > 4)
                                            {
                                                if (!RegexEmail.IsMatch(splitNewLine[1]) && !RegexHex.IsMatch(splitNewLine[1]))
                                                {
                                                    newLine = splitNewLine[1];
                                                    return true;
                                                }
                                            }
                                        }
                                    }
                                }
                                ignoreHex = true;
                                return false;

                            }

                            return true;
                        }

                    }

                }
            }

            newLine = null;
            return false;
        }

        /// <summary>
        /// Get a string between two string delimiters.
        /// </summary>
        /// <param name="str"></param>
        /// <param name="firstString"></param>
        /// <param name="lastString"></param>
        /// <returns></returns>
        public static string GetStringBetween(string str, string firstString, string lastString)
        {
            string FinalString;
            int Pos1 = str.IndexOf(firstString) + firstString.Length;
            int Pos2 = str.IndexOf(lastString);
            FinalString = str.Substring(Pos1, Pos2 - Pos1);
            return FinalString;
        }

        public static Regex RegexHex = new Regex(@"\A\b[0-9a-fA-F]+\b\Z");

        public static string RemoveControlCharacter(string line)
        {
            line = line.Replace("\x00", "");
            line = line.Replace("\x01", "");
            line = line.Replace("\x02", "");
            line = line.Replace("\x03", "");
            line = line.Replace("\x04", "");
            line = line.Replace("\x05", "");
            line = line.Replace("\x06", "");
            line = line.Replace("\x07", "");
            line = line.Replace("\x08", "");
            line = line.Replace("\x09", "");
            line = line.Replace("\x0b", "");
            line = line.Replace("\x0c", "");
            line = line.Replace("\x0d", "");
            line = line.Replace("\x0e", "");
            line = line.Replace("\x0f", "");
            line = line.Replace("\x10", "");
            line = line.Replace("\x11", "");
            line = line.Replace("\x12", "");
            line = line.Replace("\x13", "");
            line = line.Replace("\x14", "");
            line = line.Replace("\x15", "");
            line = line.Replace("\x16", "");
            line = line.Replace("\x17", "");
            line = line.Replace("\x18", "");
            line = line.Replace("\x19", "");
            line = line.Replace("\x1a", "");
            line = line.Replace("\x1b", "");
            line = line.Replace("\x1c", "");
            line = line.Replace("\x1d", "");
            line = line.Replace("\x1e", "");
            line = line.Replace("\x1f", "");
            line = line.Replace("\x7f", "");
            line = line.Replace("\x80", "");
            line = line.Replace("\x81", "");
            line = line.Replace("\x82", "");
            line = line.Replace("\x83", "");
            line = line.Replace("\x84", "");
            line = line.Replace("\x85", "");
            line = line.Replace("\x86", "");
            line = line.Replace("\x87", "");
            line = line.Replace("\x88", "");
            line = line.Replace("\x89", "");
            line = line.Replace("\x8a", "");
            line = line.Replace("\x8b", "");
            line = line.Replace("\x8c", "");
            line = line.Replace("\x8d", "");
            line = line.Replace("\x8e", "");
            line = line.Replace("\x8f", "");
            line = line.Replace("\x90", "");
            line = line.Replace("\x91", "");
            line = line.Replace("\x92", "");
            line = line.Replace("\x93", "");
            line = line.Replace("\x94", "");
            line = line.Replace("\x95", "");
            line = line.Replace("\x96", "");
            line = line.Replace("\x97", "");
            line = line.Replace("\x98", "");
            line = line.Replace("\x99", "");
            line = line.Replace("\x9a", "");
            line = line.Replace("\x9b", "");
            line = line.Replace("\x9c", "");
            line = line.Replace("\x9d", "");
            line = line.Replace("\x9e", "");
            line = line.Replace("\x9f", "");

            return line;
        }

        /// <summary>
        /// Convert a byte array to hex string like Bitconverter class.
        /// </summary>
        /// <param name="value"></param>
        /// <param name="startIndex"></param>
        /// <param name="length"></param>
        /// <param name="removeSeperator">RemoveFromCache the character '-' if true</param>
        /// <returns></returns>
        public static string GetHexStringFromByteArray(byte[] value, int startIndex, int length, bool removeSeperator = true)
        {
            int newSize = length * 3;
            char[] hexCharArray = new char[newSize];
            int currentIndex;
            for (currentIndex = 0; currentIndex < newSize; currentIndex += 3)
            {
                byte currentByte = value[startIndex++];
                hexCharArray[currentIndex] = GetHexValue(currentByte / 0x10);
                hexCharArray[currentIndex + 1] = GetHexValue(currentByte % 0x10);
                hexCharArray[currentIndex + 2] = '-';
            }
            if (removeSeperator)
            {
                return new string(hexCharArray, 0, hexCharArray.Length - 1).Replace("-", "");
            }
            return new string(hexCharArray, 0, hexCharArray.Length - 1);
        }


        /// <summary>
        /// Get Hex value from char index value.
        /// </summary>
        /// <param name="i"></param>
        /// <returns></returns>
        private static char GetHexValue(int i)
        {
            if (i < 10)
            {
                return (char)(i + 0x30);
            }
            return (char)((i - 10) + 0x41);
        }

        /// <summary>
        /// Convert a hex string into byte array.
        /// </summary>
        /// <param name="hex"></param>
        /// <returns></returns>
        public static byte[] GetByteArrayFromHexString(string hex)
        {
            try
            {
                var chars = hex.ToCharArray();
                var bytes = new List<byte>();
                for (int index = 0; index < chars.Length; index += 2)
                {
                    if (index + 2 <= chars.Length)
                    {
                        var chunk = new string(chars, index, 2);
                        bytes.Add(byte.Parse(chunk, NumberStyles.AllowHexSpecifier));
                    }
                }
                return bytes.ToArray();
            }
            catch
            {
                if (hex.Contains(":"))
                {
                    try
                    {
                        var chars = hex.Split(new[] { ":" }, StringSplitOptions.None)[1].ToCharArray();
                        var bytes = new List<byte>();
                        for (int index = 0; index < chars.Length; index += 2)
                        {

                            if (index + 2 <= chars.Length)
                            {
                                var chunk = new string(chars, index, 2);
                                bytes.Add(byte.Parse(chunk, NumberStyles.AllowHexSpecifier));
                            }

                        }
                        return bytes.ToArray();
                    }
                    catch
                    {
                        // Ignored.
                    }
                }
                if (hex.Contains(";"))
                {
                    try
                    {
                        var chars = hex.Split(new[] { ";" }, StringSplitOptions.None)[1].ToCharArray();
                        var bytes = new List<byte>();
                        for (int index = 0; index < chars.Length; index += 2)
                        {

                            if (index + 2 <= chars.Length)
                            {
                                var chunk = new string(chars, index, 2);
                                bytes.Add(byte.Parse(chunk, NumberStyles.AllowHexSpecifier));
                            }

                        }
                        return bytes.ToArray();
                    }
                    catch
                    {
                        // Ignored.
                    }
                }
                if (hex.Contains(")"))
                {
                    try
                    {
                        var chars = hex.Replace(")", "").ToCharArray();
                        var bytes = new List<byte>();
                        for (int index = 0; index < chars.Length; index += 2)
                        {

                            if (index + 2 <= chars.Length)
                            {
                                var chunk = new string(chars, index, 2);
                                bytes.Add(byte.Parse(chunk, NumberStyles.AllowHexSpecifier));
                            }

                        }
                        return bytes.ToArray();

                    }
                    catch
                    {
                        // Ignored.
                    }
                }
#if DEBUG
                Debug.WriteLine("Error on hex string: " + hex);
#endif
                return null;
            }
        }


        public static Regex RegexEmail = new Regex(@"^[\w.-]+@(?=[a-z\d][^.]*\.)[a-z\d.-]*[^.]$");

        private static List<string> _listEmailProvider = new List<string>()
        {
            ".com",
            ".fr",
            ".net",
            ".ru",
            ".co.uk",
            ".edu",
            ".co.nz",
            ".net",
            ".nl",
            ".ru",

        };

        private static List<string> _listDomain = new List<string>()
        {
            ".au",
            ".fr",
            ".com",
            ".cn",
            ".ph",
            ".hk",
            ".br",
            ".sg",
            ".es",
            ".ua",
            ".nz",
            ".il",
            ".de",
            ".my",
            ".in",
            ".edu",
            ".mk",
            ".ua",
            ".ar",
            ".vn",
            ".mx",
            ".co",
            ".be",
            ".tr",
            ".uk",
            ".tw",
            ".com.mx",
            ".pl",
            ".jo",
            ".sa",
            ".ng",
            ".ms",
            ".fj",
            ".jp",
            ".pk",
            ".ba",
            ".it",
            ".ae",
            ".mt",
            ".lb",
            ".qa",
            "b.org",
            ".org",
            ".gr",
            ".us",
            ".pa",
            ".ec",
            ".sa",
            ".na",
            ".kh",
            ".pe",
            ".pk",
            "@gmail.com",
            "gmail.com",
            ".bo",
            ".tn",
            ".vc",
            ".ve",
            ".gh",
            ".ci",
            ".ec",
            ".eg",
            "@hotmail.com",
            "@hotmail.co",
            "@hotmail",
            "hotmail",
            ".pt",
            ".np",
            ".net",
            ".se",
            ".ch",
            ".ru",
        };

        public static bool IsEmail(string line, out bool fixedLine, out string newLine)
        {

            fixedLine = false;
            newLine = string.Empty;
            Match match = RegexEmail.Match(line);
            if (match.Success)
            {
                Dictionary<string, int> validProvider = new Dictionary<string, int>();
                foreach (var provider in _listEmailProvider)
                {
                    if (line.Contains(provider))
                    {
                        if (!validProvider.ContainsKey(provider))
                            validProvider.Add(provider, 0);

                    }
                }

                if (validProvider.Count > 0)
                {
                    var providerListMaxLength = validProvider.Keys.OrderBy(x => x.Length);


                    var splitLine = line.Split(new[] { providerListMaxLength.Last() }, StringSplitOptions.None);
                    if (splitLine.Length == 2)
                    {

                        if (splitLine[1].Contains(":"))
                        {
                            var splitLineTwo = splitLine[1].Split(new[] { ":" }, StringSplitOptions.None);

                            if (splitLineTwo.Length == 2)
                            {
                                if (splitLineTwo[1].Length > 3)
                                {

                                    Match matchNewLine = RegexEmail.Match(splitLineTwo[1]);

                                    if (!matchNewLine.Success)
                                    {
                                        bool isInvalid = false;
                                        foreach (var dom in _listDomain)
                                        {
                                            if (dom == splitLineTwo[1])
                                            {
                                                isInvalid = true;
                                                break;
                                            }
                                        }

                                        if (!isInvalid)
                                        {
                                            fixedLine = true;
                                            newLine = splitLineTwo[1];
                                            if (newLine.StartsWith(".mx") && line.Contains(".com.mx"))
                                            {
                                                newLine = newLine.Replace(".mx", "");
                                            }
                                            newLine = new string(newLine.Where(c => !char.IsControl(c)).ToArray());
                                            newLine = RemoveControlCharacter(newLine);

                                            if (CheckWord(newLine) && newLine.Length > 0)
                                            {
                                                isInvalid = false;
                                                foreach (var dom in _listDomain)
                                                {
                                                    if (dom == newLine)
                                                    {
                                                        isInvalid = true;
                                                        break;
                                                    }
                                                }
                                                if (!isInvalid)
                                                {
                                                    return true;
                                                }
                                            }

                                            fixedLine = false;
                                        }
                                    }

                                }

                            }
                        }
                        else
                        {
                            if (splitLine[1].Length > 3)
                            {

                                Match matchNewLine = RegexEmail.Match(splitLine[1]);

                                if (!matchNewLine.Success)
                                {
                                    bool isInvalid = false;
                                    foreach (var dom in _listDomain)
                                    {
                                        if (dom == splitLine[1])
                                        {
                                            isInvalid = true;
                                            break;
                                        }
                                    }

                                    if (!isInvalid)
                                    {
                                        fixedLine = true;
                                        newLine = splitLine[1];
                                        if (newLine.StartsWith(".mx") && line.Contains(".com.mx"))
                                        {
                                            newLine = newLine.Replace(".mx", "");
                                        }
                                        newLine = new string(newLine.Where(c => !char.IsControl(c)).ToArray());

                                        if (CheckWord(newLine) && newLine.Length > 0)
                                        {
                                            isInvalid = false;
                                            foreach (var dom in _listDomain)
                                            {
                                                if (dom == newLine)
                                                {
                                                    isInvalid = true;
                                                    break;
                                                }
                                            }
                                            if (!isInvalid)
                                            {
                                                return true;
                                            }
                                        }

                                        fixedLine = false;

                                    }
                                }

                            }
                        }
                    }
                }


                var foo = new EmailAddressAttribute();
                if (foo.IsValid(line))
                {
                    if (line.Contains(":"))
                    {
                        var splitLine = line.Split(new[] { ":" }, StringSplitOptions.None);
                        if (splitLine.Length == 2)
                        {
                            if (splitLine[1].Length > 3)
                            {
                                Match matchNewLine = RegexEmail.Match(splitLine[1]);

                                if (!matchNewLine.Success)
                                {
                                    bool isInvalid = false;
                                    foreach (var dom in _listDomain)
                                    {
                                        if (dom == splitLine[1])
                                        {
                                            isInvalid = true;
                                            break;
                                        }
                                    }

                                    if (!isInvalid)
                                    {
                                        fixedLine = true;
                                        newLine = splitLine[1];
                                        if (newLine.StartsWith(".mx") && line.Contains(".com.mx"))
                                        {
                                            newLine = newLine.Replace(".mx", "");
                                        }
                                        newLine = new string(newLine.Where(c => !char.IsControl(c)).ToArray());

                                        newLine = RemoveControlCharacter(newLine);

                                        if (CheckWord(newLine) && newLine.Length > 0)
                                        {
                                            isInvalid = false;
                                            foreach (var dom in _listDomain)
                                            {
                                                if (dom == newLine)
                                                {
                                                    isInvalid = true;
                                                    break;
                                                }
                                            }
                                            if (!isInvalid)
                                            {
                                                return true;
                                            }
                                        }

                                        fixedLine = false;
                                    }
                                }
                            }
                        }
                    }
                    fixedLine = false;
                    newLine = string.Empty;
                    return true;
                }

                if (line.Contains("@") && line.Contains("."))
                {
                    bool email = false;

                    foreach (var tld in _listDomain)
                    {
                        if (line.Contains(tld))
                        {
                            email = true;
                            break;
                        }
                    }

                    if (email)
                    {
                        if (line.Contains(":"))
                        {
                            var splitLine = line.Split(new[] { ":" }, StringSplitOptions.None);
                            if (splitLine.Length == 2)
                            {
                                if (splitLine[1].Length > 3)
                                {
                                    Match matchNewLine = RegexEmail.Match(splitLine[1]);

                                    if (!matchNewLine.Success)
                                    {
                                        bool isInvalid = false;
                                        foreach (var dom in _listDomain)
                                        {
                                            if (dom == splitLine[1])
                                            {
                                                isInvalid = true;
                                                break;
                                            }
                                        }

                                        if (!isInvalid)
                                        {
                                            fixedLine = true;
                                            newLine = splitLine[1];
                                            if (newLine.StartsWith(".mx") && line.Contains(".com.mx"))
                                            {
                                                newLine = newLine.Replace(".mx", "");
                                            }
                                            newLine = new string(newLine.Where(c => !char.IsControl(c)).ToArray());
                                            newLine = RemoveControlCharacter(newLine);

                                            if (CheckWord(newLine) && newLine.Length > 0)
                                            {
                                                isInvalid = false;
                                                foreach (var dom in _listDomain)
                                                {
                                                    if (dom == newLine)
                                                    {
                                                        isInvalid = true;
                                                        break;
                                                    }
                                                }
                                                if (!isInvalid)
                                                {
                                                    return true;
                                                }
                                            }

                                            fixedLine = false;
                                        }
                                    }
                                }
                            }
                        }



                        fixedLine = false;
                        newLine = string.Empty;
                        return true;
                    }
                }


            }


            if (line.Contains("@") && line.Contains("."))
            {
                bool email = false;

                foreach (var tld in _listDomain)
                {
                    if (line.Contains(tld))
                    {
                        email = true;
                        break;
                    }
                }

                if (email)
                {
                    if (line.Contains(":"))
                    {
                        var splitLine = line.Split(new[] { ":" }, StringSplitOptions.None);
                        if (splitLine.Length == 2)
                        {
                            if (splitLine[1].Length > 3)
                            {
                                Match matchNewLine = RegexEmail.Match(splitLine[1]);

                                if (!matchNewLine.Success)
                                {
                                    bool isInvalid = false;
                                    foreach (var dom in _listDomain)
                                    {
                                        if (dom == splitLine[1])
                                        {
                                            isInvalid = true;
                                            break;
                                        }
                                    }

                                    if (!isInvalid)
                                    {
                                        fixedLine = true;
                                        newLine = splitLine[1];
                                        if (newLine.StartsWith(".mx") && line.Contains(".com.mx"))
                                        {
                                            newLine = newLine.Replace(".mx", "");
                                        }
                                        newLine = new string(newLine.Where(c => !char.IsControl(c)).ToArray());
                                        newLine = RemoveControlCharacter(newLine);

                                        if (CheckWord(newLine) && newLine.Length > 0)
                                        {
                                            isInvalid = false;
                                            foreach (var dom in _listDomain)
                                            {
                                                if (dom == newLine)
                                                {
                                                    isInvalid = true;
                                                    break;
                                                }
                                            }
                                            if (!isInvalid)
                                            {
                                                return true;
                                            }
                                        }

                                        fixedLine = false;
                                    }
                                }
                            }
                        }
                    }

                    fixedLine = false;
                    newLine = string.Empty;
                    return true;
                }
            }



            return false;
        }

        public static bool CheckWord(string line)
        {

            if (line.Contains("Р°") && line.Contains("РS"))
            {
                return false;
            }

            if (line.Contains("Ð°"))
            {
                return false;
            }

            int digit = 0;
            int letter = 0;
            int punctuation = 0;
            int symbol = 0;

            foreach (var character in line)
            {
                if (char.IsDigit(character))
                {
                    digit++;
                }
                if (char.IsPunctuation(character))
                {
                    punctuation++;
                }
                if (char.IsLetter(character))
                {
                    letter++;
                }
                if (char.IsSymbol(character))
                {
                    symbol++;
                }
            }

            if (digit > 0 || letter > 0 || punctuation > 0 || symbol > 0)
            {
                return true;
            }

            return false;
        }
    }
}
