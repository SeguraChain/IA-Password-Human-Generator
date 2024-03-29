﻿using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using IA_Password_Human_Generator.Object;
using IA_Password_Human_Generator.Utility;
using Newtonsoft.Json;
using Console = System.Console;

namespace IA_Password_Human_Generator
{

    class Program
    {
        /// <summary>
        /// Report of the password.
        /// </summary>
        private static IAPasswordData _iaPasswordDataObject;

        /// <summary>
        /// Task.
        /// </summary>
        private static long _currentFileLineRead;
        private static CancellationTokenSource _cancellationTokenSourceReadFile;

        /// <summary>
        /// Dictionnary used to contain lists of passwords generated from a report of password IA previously generated.
        /// </summary>
        private static Dictionary<int, FileStreamObject> fileStreamDictionnary = new Dictionary<int, FileStreamObject>();

        /// <summary>
        /// Settings.
        /// </summary>
        private const string BaseDirectoryPath = "Base\\";
        private const string DictionaryPath = "Dictionary\\";
        private const string TmpDirectory = "tmp\\";
        private const int MininumCharacter = 7;
        private const int MaxTaskReadFile = 3;
        private const int MaxLignePerFile = 10000000;
        private const int MaxLignePerFileGenerated = 10000;

        /// <summary>
        /// Stats.
        /// </summary>
        public static long TotalLineFile;





        static void Main(string[] args)
        {

            ClassRamStatus.EnableRamCounterTask();

            if (!Directory.Exists(AppContext.BaseDirectory + "\\" + TmpDirectory))
                Directory.CreateDirectory(AppContext.BaseDirectory + "\\" + TmpDirectory);

            if (!Directory.Exists(AppContext.BaseDirectory + "\\" + BaseDirectoryPath))
                Directory.CreateDirectory(AppContext.BaseDirectory + "\\" + BaseDirectoryPath);

            if (!Directory.Exists(AppContext.BaseDirectory + "\\" + BaseDirectoryPath + "\\"+DictionaryPath))
                Directory.CreateDirectory(AppContext.BaseDirectory + "\\" + BaseDirectoryPath + "\\" + DictionaryPath);

            ShowMainMenu();

            Console.WriteLine("Press a key to close the program.");
            Console.ReadLine();
        }

        /// <summary>
        /// Display of main menus.
        /// </summary>
        private static void ShowMainMenu()
        {
            Console.WriteLine("Choose a function to use:");
            Console.WriteLine("1. Generate a report from a list of passwords.");
            Console.WriteLine("2. Use a report generated for generate predicated from password.");
            Console.WriteLine("3. Erase duplicate lines from a list of password.");
            Console.WriteLine("4. Erase too short password from a list (Edit the source code of the program if necessary).");
            Console.WriteLine("5. Read lines of a file for fix them.");
            Console.WriteLine("6. Join file into a big one file.");
            Console.WriteLine("7. Cut a big a file into multiple files.");
            Console.WriteLine("8. Close the program.");
            string choose = Console.ReadLine() ?? string.Empty;

            bool validChoose = false;

            while (!validChoose)
            {


                while (!int.TryParse(choose, out _))
                {
                    Console.WriteLine("Choose a function to use:");
                    Console.WriteLine("1. Generate a report from a list of passwords.");
                    Console.WriteLine("2. Use a report generated for generate predicated from password.");
                    Console.WriteLine("3. Erase duplicate lines from a list of password.");
                    Console.WriteLine("4. Erase too short password from a list (Edit the source code of the program if necessary).");
                    Console.WriteLine("5. Read lines of a file for fix them.");
                    Console.WriteLine("6. Join files into a big one file.");
                    Console.WriteLine("7. Cut a big a file into multiple files.");
                    Console.WriteLine("8. Close the program.");
                    choose = Console.ReadLine() ?? string.Empty;
                }
                switch (choose)
                {
                    case "1":
                    case "2":
                    case "3":
                    case "4":
                    case "5":
                    case "6":
                    case "7":
                    case "8":
                        validChoose = true;
                        break;

                }
            }

            switch (choose)
            {
                case "1":
                    BuildAiPasswordRapportData();
                    CleanUp();
                    ShowMainMenu();
                    break;
                case "2":
                    BuildPasswordFromAiRapportData();
                    CleanUp();
                    ShowMainMenu();
                    break;
                case "3":
                    RemoveDuplicateLineFromFile();
                    CleanUp();
                    ShowMainMenu();
                    break;
                case "4":
                    RemoveTooLowCharactersLengthLineFromFile();
                    CleanUp();
                    ShowMainMenu();
                    break;
                case "5":
                    CorrectPasswordList();
                    CleanUp();
                    ShowMainMenu();
                    break;
                case "6":
                    MergeFileInOne();
                    CleanUp();
                    ShowMainMenu();
                    break;
                case "7":
                    SplitFile();
                    CleanUp();
                    ShowMainMenu();
                    break;
            }
        }

        /// <summary>
        ///  Clean up memory.
        /// </summary>
        private static void CleanUp()
        {
            TotalLineFile = 0;
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
        }

        /// <summary>
        /// Generates a password report from a target file.
        /// </summary>
        private static void BuildAiPasswordRapportData()
        {
            _iaPasswordDataObject = new IAPasswordData();
            Console.WriteLine("Choose the file who contain passwords:");

            string fichier = Console.ReadLine() ?? string.Empty;

            if (File.Exists(fichier))
            {


                using (FileStream fs = File.Open(fichier, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (BufferedStream bs = new BufferedStream(fs, 8192))
                {
                    Console.WriteLine("Count lines, please wait a moment..");

                    TotalLineFile = CountLinesMaybe(bs);
                    Console.WriteLine("Number of line(s) to load: " + $"{TotalLineFile:#,##0.##}");
                }


                Console.WriteLine("Check of the file: " + fichier + "..");
                StartTaskFileRead(fichier);


                using (FileStream fs = File.Open(fichier, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                using (BufferedStream bs = new BufferedStream(fs, 81920))
                using (StreamReader sr = new StreamReader(bs, Encoding.UTF8))
                {
                    List<string> ligneListe = new List<string>();

                    string ligne;

                    while ((ligne = sr.ReadLine()) != null)
                    {
                        ligneListe.Add(ligne);

                        if (ligneListe.Count >= 10000000)
                        {
                            ligneListe.AsParallel().WithDegreeOfParallelism(MaxTaskReadFile).ForAll(ReadPasswordLine);
                            ligneListe.Clear();
                        }
                    }

                    if (ligneListe.Count > 0)
                    {
                        ligneListe.AsParallel().WithDegreeOfParallelism(MaxTaskReadFile).ForAll(ReadPasswordLine);
                        ligneListe.Clear();
                    }
                }

                CloseTaskFileRead();


                _iaPasswordDataObject.TotalPassword = _currentFileLineRead;
                Console.WriteLine("Total password passed(s): " + _currentFileLineRead);
                Console.WriteLine("Save of the report in progress..");
                using (StreamWriter writer = new StreamWriter("ia-data-password-generated-" + DateTimeOffset.Now.ToUnixTimeSeconds() + ".json"))
                    writer.Write(JsonConvert.SerializeObject(_iaPasswordDataObject, Formatting.Indented));


                Console.WriteLine("Check of the file: " + fichier + " done. Report saved.");
            }
            else
                Console.WriteLine("The file not exist.");

        }

        private static SemaphoreSlim semaphoreWritePassword = new SemaphoreSlim(1, 1);

        /// <summary>
        /// Generate passwords from datas of a report.
        /// </summary>
        private static void BuildPasswordFromAiRapportData()
        {
            Console.WriteLine("Write the path of the file the IA password report:");
            string chemin = Console.ReadLine() ?? string.Empty;

            if (File.Exists(chemin))
            {
                Console.WriteLine("Load of the report done..");

                _iaPasswordDataObject = JsonConvert.DeserializeObject<IAPasswordData>(string.Concat(File.ReadAllLines(chemin)));

                if (_iaPasswordDataObject == null)
                    Console.WriteLine("The file: " + chemin + " is empty or invalid, can't use the report content of this file.");
                else
                {

                    #region Lecture rapport de mot de passe.

                    Console.WriteLine("Load of the report done.");

                    long quantiteMotDePasse = 0;

                    Console.WriteLine("Please, input the quantity of valid password to generate: ");
                    string quantiteMotDePasseSaisie = Console.ReadLine() ?? string.Empty;

                    while (quantiteMotDePasse <= 0)
                    {
                        while (!long.TryParse(quantiteMotDePasseSaisie, out quantiteMotDePasse))
                        {
                            Console.WriteLine("Please, input the quantity of valid password to generate: ");
                            quantiteMotDePasseSaisie = Console.ReadLine() ?? string.Empty;
                        }

                        if (quantiteMotDePasse <= 0)
                        {
                            Console.WriteLine("The input quantity is invalid, the quantity need to be above 0.");
                            Console.WriteLine("Please, input the quantity of valid password to generate: ");
                            quantiteMotDePasseSaisie = Console.ReadLine() ?? string.Empty;
                        }
                    }

                    Console.WriteLine("Do you want to use dictionaries of basewords to generate password ? [Y/N]");

                    string choose = Console.ReadLine() ?? string.Empty;

                    bool useBaseDictionnary = choose.ToLower() == "y";

                    Dictionary<string, int> dictionaryCorrespondanceMot = new Dictionary<string, int>();

                    if (useBaseDictionnary)
                    {
                        if (!Directory.Exists(AppContext.BaseDirectory + "\\" + BaseDirectoryPath + "\\" + DictionaryPath))
                        {
                            Console.WriteLine("Unable to load the list of wordbases, disabling generation of passwords by correspondence.");
                            useBaseDictionnary = false;
                        }
                        else
                        {
                            string[] listeFichier = Directory.GetFiles(AppContext.BaseDirectory + "\\" + BaseDirectoryPath + "\\" + DictionaryPath, "*.txt", SearchOption.TopDirectoryOnly);

                            if (listeFichier.Length == 0)
                            {
                                Console.WriteLine("No files available, disabling password generation by correspondence.");
                                useBaseDictionnary = false;
                            }
                            else
                            {
                                foreach (var fichierBase in listeFichier)
                                {
                                    if (!string.IsNullOrEmpty(fichierBase))
                                    {
                                        if (File.Exists(fichierBase))
                                        {
                                            Console.WriteLine("Do you want to upload the file: " + fichierBase + "? [Y/N]");

                                            choose = Console.ReadLine() ?? string.Empty;

                                            if (choose.ToLower() == "y")
                                            {
                                                using (StreamReader readerBase = new StreamReader(fichierBase))
                                                {
                                                    string ligne;

                                                    while ((ligne = readerBase.ReadLine()) != null)
                                                    {
                                                        if (!dictionaryCorrespondanceMot.ContainsKey(ligne.ToLower()))
                                                            dictionaryCorrespondanceMot.Add(ligne.ToLower(), 0);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                if (dictionaryCorrespondanceMot.Count == 0)
                                {
                                    Console.WriteLine("No words contained in the lists available. disabling generation of passwords by correspondence.");
                                    useBaseDictionnary = false;
                                }
                            }
                        }
                    }

                    Console.WriteLine("Generation of stats according to the report..");

                    Stopwatch watchStopwatch = new Stopwatch();

                    watchStopwatch.Start();

                    #endregion

                    #region Generation of percentage rates of password lengths.

                    Dictionary<decimal, decimal> dictionaryPasswordLengthPercent = new Dictionary<decimal, decimal>();

                    decimal sumOfLength = _iaPasswordDataObject.PasswordLengthRank.Sum(k => k.Value);

                    Debug.WriteLine("Max character sum of length: " + sumOfLength);

                    foreach (var rank in _iaPasswordDataObject.PasswordLengthRank)
                    {
                        decimal percent = 0;

                        if (rank.Value > 0)
                            percent = ((rank.Value / sumOfLength) * 100m);

                        Debug.WriteLine(percent);

                        if (percent > 0)
                            dictionaryPasswordLengthPercent.Add(rank.Key, percent);
                    }

                    #endregion

                    #region Generating percentage usage rates of password characters.

                    Dictionary<char, decimal> dictionaryPasswordCharacterPercent = new Dictionary<char, decimal>();

                    decimal sumOfPasswordCharacterLength = _iaPasswordDataObject.PasswordCharacterRank.Values.Sum(k => k);

                    Debug.WriteLine("Sum of password character length: " + sumOfPasswordCharacterLength);

                    foreach (var rank in _iaPasswordDataObject.PasswordCharacterRank)
                    {
                        decimal percent = 0;

                        if (rank.Value > 0)
                        {
                            percent = ((rank.Value / sumOfPasswordCharacterLength) * 100m);

                            Debug.WriteLine(percent);

                            if (percent > 0)
                                dictionaryPasswordCharacterPercent.Add(rank.Key, percent);
                        }
                    }

                    #endregion

                    #region Generating position-based password character usage percentage rates.

                    Dictionary<decimal, Dictionary<char, decimal>> dictionaryPasswordCharacterPositionPercent = new Dictionary<decimal, Dictionary<char, decimal>>();

                    foreach (var posRank in _iaPasswordDataObject.PasswordPosRank)
                    {
                        dictionaryPasswordCharacterPositionPercent.Add(posRank.Key, new Dictionary<char, decimal>());

                        if (posRank.Value.Count > 0)
                        {
                            decimal sumCharacter = posRank.Value.Values.Sum();

                            foreach (var rank in posRank.Value)
                            {
                                if (rank.Value > 0)
                                {
                                    decimal percent = ((rank.Value / sumCharacter) * 100m);

                                    if (percent > 0)
                                        dictionaryPasswordCharacterPositionPercent[posRank.Key].Add(rank.Key, percent);
                                }
                            }
                        }
                    }

                    #endregion

                    #region Creating the first temporary file and folder containing this.

                    Console.WriteLine("Generation of percentage stats based on completed report.");

                    Console.WriteLine("Generation of: " + quantiteMotDePasse + " password(s) according to the report..");

                    string fichier = "password-list-" + DateTimeOffset.Now.ToUnixTimeSeconds() + ".txt";

                    File.Create(fichier).Close();

                    if (!Directory.Exists(TmpDirectory))
                        Directory.CreateDirectory(TmpDirectory);

                    int currentFileStreamIndex = 0;

                    fileStreamDictionnary.Add(currentFileStreamIndex, new FileStreamObject());
                    fileStreamDictionnary[currentFileStreamIndex].NameFile = TmpDirectory + "\\" + fichier + currentFileStreamIndex;
                    File.Create(fileStreamDictionnary[currentFileStreamIndex].NameFile).Close();
                    fileStreamDictionnary[currentFileStreamIndex].FileStreamWriter = new FileStream(fileStreamDictionnary[currentFileStreamIndex].NameFile, FileMode.Append, FileAccess.Write, FileShare.Read);
                    fileStreamDictionnary[currentFileStreamIndex].FileStreamReader = new FileStream(fileStreamDictionnary[currentFileStreamIndex].NameFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                    fileStreamDictionnary[currentFileStreamIndex].StreamReader = new StreamReader(fileStreamDictionnary[currentFileStreamIndex].FileStreamReader);
                    fileStreamDictionnary[currentFileStreamIndex].StreamWriter = new StreamWriter(fileStreamDictionnary[currentFileStreamIndex].FileStreamWriter) { AutoFlush = true };

                    #endregion

                    #region Max Stats.

                    long totalToDo = quantiteMotDePasse;

                    decimal maxPasswordLengthValue = dictionaryPasswordLengthPercent.Values.Max();
                    decimal maxPasswordCharacterValue = dictionaryPasswordCharacterPercent.Values.Max();

                    #endregion

                    for (int i = 0; i < Environment.ProcessorCount / 2; i++)
                    {
                        try
                        {
                            Task.Factory.StartNew(() =>
                            {
                                while (totalToDo > 0)
                                {

                                    #region Select the length of the password to be generated.

                                    int passwordLengthSelected = 0;

                                    decimal percentSelected = GetRandomBetween(0, maxPasswordLengthValue);

                                    while (passwordLengthSelected < MininumCharacter)
                                    {
                                        if (dictionaryPasswordLengthPercent.ContainsKey(percentSelected))
                                        {
                                            if (dictionaryPasswordLengthPercent[percentSelected] > MininumCharacter)
                                            {
                                                passwordLengthSelected = (int)dictionaryPasswordLengthPercent[percentSelected];
                                                break;
                                            }
                                        }

                                        percentSelected = GetRandomBetween(0, maxPasswordLengthValue);
                                    }

                                    #endregion


                                    if (passwordLengthSelected > 0)
                                    {
                                        string passwordGenerated = string.Empty;
                                        decimal accumulator = 0;

                                        while (passwordGenerated.Length < passwordLengthSelected)
                                        {
                                            bool cancelCaracter = false;
                                            accumulator = 0;

                                            decimal maxPercent = dictionaryPasswordCharacterPositionPercent[dictionaryPasswordCharacterPositionPercent.Count - 1].Last().Value;

                                            decimal percentCharacterSelect = GetRandomBetween(0, maxPercent);

                                            while (percentCharacterSelect == 0)
                                                percentCharacterSelect = GetRandomBetween(0, maxPercent);

                                            string characterSelectionner = string.Empty;
                                            foreach (var characterRank in dictionaryPasswordCharacterPercent)
                                            {
                                                accumulator += characterRank.Value;
                                                if (accumulator >= percentCharacterSelect)
                                                {
                                                    characterSelectionner = characterRank.Key.ToString();
                                                    break;
                                                }
                                            }

                                            if (!cancelCaracter)
                                            {
                                                if (!string.IsNullOrEmpty(characterSelectionner))
                                                {
                                                    if (dictionaryPasswordCharacterPositionPercent.ContainsKey(passwordLengthSelected))
                                                    {
                                                        accumulator = 0;

                                                        decimal pourcentCharacterSelectPos = GetRandomBetween(0m, 100m);

                                                        foreach (var characterRank in dictionaryPasswordCharacterPositionPercent[passwordLengthSelected])
                                                        {
                                                            accumulator += characterRank.Value;
                                                            if (accumulator >= pourcentCharacterSelectPos)
                                                            {
                                                                if (characterRank.Key.ToString() == characterSelectionner)
                                                                    passwordGenerated += characterSelectionner;

                                                                break;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        if (passwordGenerated.Length >= MininumCharacter)
                                        {
                                            if (useBaseDictionnary)
                                            {
                                                bool corresponding = false;
                                                foreach (var password in dictionaryCorrespondanceMot)
                                                {
                                                    if (passwordGenerated.ToLower().Contains(password.Key))
                                                    {
                                                        corresponding = true;
                                                        break;
                                                    }
                                                }

                                                if (corresponding)
                                                {
                                                    totalToDo--;
                                                    fileStreamDictionnary[currentFileStreamIndex].ListWord.Add(passwordGenerated);
                                                    fileStreamDictionnary[currentFileStreamIndex].Total++;

#if DEBUG
                                                    Debug.WriteLine("Total passwords generated on current index: " + fileStreamDictionnary[currentFileStreamIndex].Total + " | total to do: " + totalToDo);
#endif

                                                    if (fileStreamDictionnary[currentFileStreamIndex].Total >= MaxLignePerFileGenerated)
                                                    {
                                                        try
                                                        {
                                                            semaphoreWritePassword.Wait();

                                                            if (fileStreamDictionnary[currentFileStreamIndex].ListWord.Count > 0)
                                                            {
                                                                foreach (string password in fileStreamDictionnary[currentFileStreamIndex].ListWord)
                                                                    fileStreamDictionnary[currentFileStreamIndex].StreamWriter.WriteLine(password);

                                                                fileStreamDictionnary[currentFileStreamIndex].ListWord.Clear();

                                                                currentFileStreamIndex++;
                                                                fileStreamDictionnary.Add(currentFileStreamIndex, new FileStreamObject());
                                                                fileStreamDictionnary[currentFileStreamIndex].NameFile = TmpDirectory + "\\" + fichier + currentFileStreamIndex;
                                                                File.Create(fileStreamDictionnary[currentFileStreamIndex].NameFile).Close();
                                                                fileStreamDictionnary[currentFileStreamIndex].FileStreamWriter = new FileStream(fileStreamDictionnary[currentFileStreamIndex].NameFile, FileMode.Append, FileAccess.Write, FileShare.Read);
                                                                fileStreamDictionnary[currentFileStreamIndex].FileStreamReader = new FileStream(fileStreamDictionnary[currentFileStreamIndex].NameFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                                                fileStreamDictionnary[currentFileStreamIndex].StreamReader = new StreamReader(fileStreamDictionnary[currentFileStreamIndex].FileStreamReader);
                                                                fileStreamDictionnary[currentFileStreamIndex].StreamWriter = new StreamWriter(fileStreamDictionnary[currentFileStreamIndex].FileStreamWriter);
                                                            }
                                                        }
                                                        finally
                                                        {
                                                            semaphoreWritePassword.Release();
                                                        }
                                                    }
                                                }
                                            }
                                            else
                                            {

                                                totalToDo--;
                                                fileStreamDictionnary[currentFileStreamIndex].StreamWriter.WriteLine(passwordGenerated);
                                                fileStreamDictionnary[currentFileStreamIndex].Total++;


#if DEBUG
                                                Debug.WriteLine("Total passwords generated on current index: " + fileStreamDictionnary[currentFileStreamIndex].Total + " | total to do: " + totalToDo);
#endif

                                                if (fileStreamDictionnary[currentFileStreamIndex].Total >= MaxLignePerFileGenerated)
                                                {
                                                    try
                                                    {
                                                        semaphoreWritePassword.Wait();

                                                        if (fileStreamDictionnary[currentFileStreamIndex].ListWord.Count > 0)
                                                        {
                                                            foreach (string password in fileStreamDictionnary[currentFileStreamIndex].ListWord)
                                                                fileStreamDictionnary[currentFileStreamIndex].StreamWriter.WriteLine(password);

                                                            fileStreamDictionnary[currentFileStreamIndex].ListWord.Clear();

                                                            currentFileStreamIndex++;
                                                            fileStreamDictionnary.Add(currentFileStreamIndex, new FileStreamObject());
                                                            fileStreamDictionnary[currentFileStreamIndex].NameFile = TmpDirectory + "\\" + fichier + currentFileStreamIndex;
                                                            File.Create(fileStreamDictionnary[currentFileStreamIndex].NameFile).Close();
                                                            fileStreamDictionnary[currentFileStreamIndex].FileStreamWriter = new FileStream(fileStreamDictionnary[currentFileStreamIndex].NameFile, FileMode.Append, FileAccess.Write, FileShare.Read);
                                                            fileStreamDictionnary[currentFileStreamIndex].FileStreamReader = new FileStream(fileStreamDictionnary[currentFileStreamIndex].NameFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                                                            fileStreamDictionnary[currentFileStreamIndex].StreamReader = new StreamReader(fileStreamDictionnary[currentFileStreamIndex].FileStreamReader);
                                                            fileStreamDictionnary[currentFileStreamIndex].StreamWriter = new StreamWriter(fileStreamDictionnary[currentFileStreamIndex].FileStreamWriter);
                                                        }
                                                    }
                                                    finally
                                                    {
                                                        semaphoreWritePassword.Release();
                                                    }
                                                }
                                            }
                                        }
                                    }

                                }
                            }).ConfigureAwait(false);
                        }
                        catch
                        {
                            // Ignored.
                        }
                    }

                    new Thread(() =>
                    {
                        while (totalToDo > 0)
                            Thread.Sleep(1000);

                        Console.WriteLine("List of password(s) successfully generated. Merging files in progress..");

                        using (StreamWriter writer = new StreamWriter(fichier) { AutoFlush = true })
                        {
                            foreach (var streamObject in fileStreamDictionnary)
                            {
                                string ligne;

                                fileStreamDictionnary[streamObject.Key].StreamReader.BaseStream.Seek(0, SeekOrigin.Begin);
                                fileStreamDictionnary[streamObject.Key].StreamReader.BaseStream.Position = 0;

                                while ((ligne = fileStreamDictionnary[streamObject.Key].StreamReader.ReadLine()) != null)
                                    writer.WriteLine(ligne);

                                fileStreamDictionnary[streamObject.Key].StreamReader.Close();
                                fileStreamDictionnary[streamObject.Key].StreamWriter.Close();
                                fileStreamDictionnary[streamObject.Key].FileStreamReader.Close();
                                fileStreamDictionnary[streamObject.Key].FileStreamWriter.Close();
                                File.Delete(fileStreamDictionnary[streamObject.Key].NameFile);
                            }
                        }

                        watchStopwatch.Stop();

                        Console.WriteLine("File(s) merged successfully. Total generated passwords: " + quantiteMotDePasse);
                        Console.WriteLine("Timespent: " + watchStopwatch.ElapsedMilliseconds / 1000 + " second(s).");

                    }).Start();
                }
            }
            else
            {
                Console.WriteLine("The file: " + chemin + " not exist.");
            }
        }

        /// <summary>
        /// Remove duplicate rows.
        /// </summary>
        private static void RemoveDuplicateLineFromFile()
        {
            Console.WriteLine("Enter the path of the file to process: ");
            string file = Console.ReadLine();

            Console.WriteLine("Enter the save path: ");
            string sauvegarde = Console.ReadLine();

            Console.WriteLine("Enter the temporary path:");
            string temp = Console.ReadLine();

            Console.WriteLine("Enter the path to merge temporary files (Useful to lighten the load of a hard disk):");
            string tempBigMerge = Console.ReadLine();

            if (File.Exists(file))
            {

                bool continueSort = false;

                if (!Directory.Exists(temp))
                    Directory.CreateDirectory(temp);
                else
                {
                    if (Directory.GetFiles(temp, "*.txt", SearchOption.TopDirectoryOnly).Length > 0)
                    {
                        Console.WriteLine("Temporary files were found, do you want to resume the previous job? [Y/N]");

                        string choose = Console.ReadLine() ?? string.Empty;

                        bool continueInputChoose = false;

                        if (choose.ToLower() != "y")
                        {
                            if (choose.ToLower() != "n")
                                continueInputChoose = true;
                        }

                        while (continueInputChoose)
                        {
                            Console.WriteLine("The input is invalid.");
                            Console.WriteLine("Temporary files were found, do you want to resume the previous job? [Y/N]");
                            choose = Console.ReadLine() ?? string.Empty;
                            if (choose.ToLower() != "y")
                            {
                                if (choose.ToLower() != "n")
                                    continueInputChoose = false;
                            }
                            else
                                continueInputChoose = false;
                        }

                        if (choose.ToLower() == "y")
                            continueSort = true;

                    }
                }


                List<string> listeFichierTemporaire = new List<string>();

                if (!continueSort)
                {
                    Console.WriteLine("Generation of temporary files in progress..");

                    int idFichierTemp = 0;

                    listeFichierTemporaire.Add(temp + "\\temp-" + idFichierTemp + ".txt");

                    Dictionary<int, StreamWriterObject> listFileStreamTemp = new Dictionary<int, StreamWriterObject>();

                    listFileStreamTemp.Add(idFichierTemp, new StreamWriterObject()
                    {
                        FileStreamWriter = new FileStream(listeFichierTemporaire[idFichierTemp], FileMode.Append, FileAccess.Write, FileShare.Read),
                        FileStreamReader = new FileStream(listeFichierTemporaire[idFichierTemp], FileMode.Open, FileAccess.Read, FileShare.ReadWrite),
                        Total = 0
                    });

                    listFileStreamTemp[idFichierTemp].StreamWriter = new StreamWriter(listFileStreamTemp[idFichierTemp].FileStreamWriter);
                    listFileStreamTemp[idFichierTemp].StreamReader = new StreamReader(listFileStreamTemp[idFichierTemp].FileStreamReader);

                    Dictionary<string, int> dictionaryTmpRead = new Dictionary<string, int>();

                    using (StreamReader reader = new StreamReader(file))
                    {
                        string ligne;

                        while ((ligne = reader.ReadLine()) != null)
                        {
                            if (!dictionaryTmpRead.ContainsKey(ligne))
                            {
                                listFileStreamTemp[idFichierTemp].StreamWriter.WriteLine(ligne);
                                listFileStreamTemp[idFichierTemp].Total++;
                                dictionaryTmpRead.Add(ligne, 0);

                                if (listFileStreamTemp[idFichierTemp].Total >= MaxLignePerFile)
                                {
                                    idFichierTemp++;
                                    dictionaryTmpRead.Clear();
                                    listeFichierTemporaire.Add(temp + "\\temp-" + idFichierTemp + ".txt");
                                    listFileStreamTemp.Add(idFichierTemp, new StreamWriterObject()
                                    {
                                        FileStreamWriter = new FileStream(listeFichierTemporaire[idFichierTemp], FileMode.Append, FileAccess.Write, FileShare.Read),
                                        FileStreamReader = new FileStream(listeFichierTemporaire[idFichierTemp], FileMode.Open, FileAccess.Read, FileShare.ReadWrite),
                                        Total = 0
                                    });

                                    listFileStreamTemp[idFichierTemp].StreamWriter = new StreamWriter(listFileStreamTemp[idFichierTemp].FileStreamWriter);
                                    listFileStreamTemp[idFichierTemp].StreamReader = new StreamReader(listFileStreamTemp[idFichierTemp].FileStreamReader);

                                }
                            }
                        }
                    }

                    dictionaryTmpRead.Clear();

                    foreach (var streamWriterObject in listFileStreamTemp)
                    {
                        listFileStreamTemp[streamWriterObject.Key].StreamReader.Close();
                        listFileStreamTemp[streamWriterObject.Key].StreamWriter.Close();
                        listFileStreamTemp[streamWriterObject.Key].FileStreamReader.Close();
                        listFileStreamTemp[streamWriterObject.Key].FileStreamWriter.Close();
                    }
                    Console.WriteLine("Temporary file created successfully. Total: " + listFileStreamTemp.Count);

                }
                else
                {
                    Console.WriteLine("Resuming work in progress..");
                    listeFichierTemporaire = Directory.GetFiles(temp, "*.txt", SearchOption.TopDirectoryOnly).ToList();
                }


                Console.WriteLine("Merging temporary files in progress..");

                string bigMerge = tempBigMerge + "\\big\\";
                string bigMergeFile = bigMerge + "big-data.txt";

                if (!Directory.Exists(bigMerge))
                    Directory.CreateDirectory(bigMerge);
                

                Dictionary<string, int> bigTrieDictionnary = new Dictionary<string, int>();
                int countDictionnary = 0;

                using (FileStream bigMergeWriter = new FileStream(bigMergeFile, FileMode.Append, FileAccess.Write, FileShare.Read))
                {
                    using (StreamWriter writer = new StreamWriter(bigMergeWriter))
                    {

                        foreach (var ligne in File.ReadAllLines(listeFichierTemporaire[0]))
                        {
                            if (ligne.Length >= MininumCharacter)
                            {
                                if (!bigTrieDictionnary.ContainsKey(ligne))
                                {
                                    if (ClassRamStatus.RamAvailableStatus())
                                        bigTrieDictionnary.Add(ligne, 0);
                                    else
                                    {
                                        if (countDictionnary == 2)
                                        {
                                            countDictionnary = 0;
                                            bigTrieDictionnary.Clear();
                                        }

                                    }
                                    writer.WriteLine(ligne);
                                }
                            }
                        }

                        countDictionnary++;

                        for (int i = 0; i < listeFichierTemporaire.Count; i++)
                        {
                            if (i != 0)
                            {
                                if (i < listeFichierTemporaire.Count)
                                {
                                    foreach (var ligne in File.ReadAllLines(listeFichierTemporaire[i]))
                                    {
                                        if (ligne.Length >= MininumCharacter)
                                        {
                                            if (!bigTrieDictionnary.ContainsKey(ligne))
                                            {
                                                if (ClassRamStatus.RamAvailableStatus())
                                                    bigTrieDictionnary.Add(ligne, 0);
                                                else
                                                {
                                                    if (countDictionnary == 2)
                                                    {
                                                        countDictionnary = 0;
                                                        bigTrieDictionnary.Clear();
                                                    }

                                                }
                                                writer.WriteLine(ligne);
                                            }
                                        }
                                    }
                                    countDictionnary++;
                                }
                            }
                        }
                    }
                }

                bigTrieDictionnary.Clear();

                Console.WriteLine("Merging temporary files in progress..");


                File.Create(sauvegarde).Close();

                long totalLigne = 0;

                using (var fileStreamWriterSave = new FileStream(sauvegarde, FileMode.Append, FileAccess.Write, FileShare.Read))
                {
                    using (var fileStreamReaderSave = new FileStream(sauvegarde, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                    {
                        using (StreamReader readerSave = new StreamReader(fileStreamReaderSave))
                        {
                            using (StreamWriter writerSave = new StreamWriter(fileStreamWriterSave))
                            {

                                using (StreamReader readerTemp = new StreamReader(bigMergeFile))
                                {
                                    string ligne;

                                    while ((ligne = readerTemp.ReadLine()) != null)
                                    {
                                        bool existe = false;

                                        readerSave.BaseStream.Seek(0, SeekOrigin.Begin);
                                        readerSave.BaseStream.Position = 0;

                                        string ligneCheck;

                                        while ((ligneCheck = readerSave.ReadLine()) != null)
                                        {
                                            if (ligneCheck == ligne)
                                            {
                                                existe = true;
                                                break;
                                            }
                                        }

                                        if (!existe)
                                        {
                                            totalLigne++;
                                            writerSave.WriteLine(ligne);
                                        }
                                    }
                                }

                            }
                        }
                    }
                }

                Console.WriteLine("File processed successfully. Total unique rows saved: " + totalLigne);

                Console.WriteLine("Do you want to delete the temporary ones? [Y/N]");

                string chooseRemove = Console.ReadLine() ?? string.Empty;

                if (chooseRemove.ToLower() == "y")
                {
                    Console.WriteLine("Deletion of current temporaries..");
                    Directory.Delete(temp);
                    Console.WriteLine("Deletion of terminated temporaries.");
                }
            }
            else
            {
                Console.WriteLine("The file: " + file + " not exist.");
            }
        }

        /// <summary>
        /// Deletes the lines which have a number of characters lower than the chosen limit.
        /// </summary>
        private static void RemoveTooLowCharactersLengthLineFromFile()
        {
            Console.WriteLine("Password file path too short to delete:");
            string fichierSource = Console.ReadLine();

            Console.WriteLine("Backup path:");
            string fichierDestination = Console.ReadLine();

            using (FileStream fs = File.Open(fichierSource, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (BufferedStream bs = new BufferedStream(fs, 8192))
            {
                Console.WriteLine("Counting the number of rows..");

                TotalLineFile = CountLinesMaybe(bs);
                Console.WriteLine("Number of line(s) to load: " + $"{TotalLineFile:#,##0.##}");
            }


            Console.WriteLine("Ongoing treatment..");

            long totalLigneLu = 0;
            bool finish = false;

            Task.Factory.StartNew(async () =>
            {
                while (!finish)
                {
                    Debug.WriteLine("Total Rows Processed: " + totalLigneLu + "/" + TotalLineFile);
                    await Task.Delay(1000);
                }
            }).ConfigureAwait(false);

            using (StreamReader reader = new StreamReader(fichierSource))
            {
                using (StreamWriter writer = new StreamWriter(fichierDestination))
                {
                    string line;
                    while ((line = reader.ReadLine()) != null)
                    {
                        if (line.Length >= MininumCharacter)
                            writer.WriteLine(line);

                        totalLigneLu++;
                    }
                }
            }
            finish = true;

            Console.WriteLine("Processing completed.");
            Console.ReadLine();
        }

        /// <summary>
        /// Fix password lines, convert lines that are in HEX format to string with the best possible encoding.
        /// </summary>
        private static void CorrectPasswordList()
        {
            TotalLineFile = 0;
            Console.WriteLine("Path of the password file to correct: ");
            string fichierSource = Console.ReadLine();

            Console.WriteLine("Backup path: ");
            string fichierDestination = Console.ReadLine();

            Console.WriteLine("Overwrite other valid lines? [Y/N]:");

            string choose = Console.ReadLine() ?? string.Empty;

            bool rewriteLines = choose.ToLower() == "y";

            Console.WriteLine("Execute a simple line split? [Y/N]:");
            choose = Console.ReadLine() ?? string.Empty;
            bool simpleSplit = choose.ToLower() == "y";
            
            using (FileStream fs = File.Open(fichierSource, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (BufferedStream bs = new BufferedStream(fs, 8192))
            {
                Console.WriteLine("Counting the number of rows..");

                TotalLineFile = CountLinesMaybe(bs);
                Console.WriteLine("Number of line(s) to load: " + $"{TotalLineFile:#,##0.##}");
            }
            

            Console.WriteLine("Ongoing treatment..");

            long totalReadLine = 0;
            long totalEdited = 0;
            bool finish = false;

            Task.Factory.StartNew(async () =>
            {
                while (!finish)
                {
                    Debug.WriteLine("Total rows processed: " + totalReadLine + "/" + TotalLineFile);
                    Debug.WriteLine("Total Rows Modified: " + totalEdited + "/" + TotalLineFile);

                    await Task.Delay(1000);
                }
            }).ConfigureAwait(false);

            var textDetect = new TextEncodingDetect();


            HashSet<string> listPass = new HashSet<string>();

            UTF8Encoding utf8Encoding = new UTF8Encoding(false);

            using (StreamReader reader = new StreamReader(fichierSource, utf8Encoding))
            {
                using (StreamWriter writer = new StreamWriter(fichierDestination, false, utf8Encoding) {AutoFlush = true})
                {
                    using (StreamWriter writerInvalid = new StreamWriter(fichierDestination + "-invalid.txt", false, utf8Encoding))
                    {
                        if (!simpleSplit)
                        {

                            using (StreamWriter writerEmail = new StreamWriter(fichierDestination + "-email.txt", false, utf8Encoding) { AutoFlush = true })
                            {
                                using (StreamWriter writerBadEncoding = new StreamWriter(fichierDestination + "-bad-encoding.txt", false, utf8Encoding) { AutoFlush = true })
                                {
                                    using (StreamWriter writerEdited = new StreamWriter(fichierDestination + "-edited.txt", false, utf8Encoding) { AutoFlush = true })
                                    {
                                        string line;
                                        while ((line = reader.ReadLine()) != null)
                                        {
                                            line = new string(line.Where(c => !char.IsControl(c)).ToArray());

                                            bool containHexString = false;

                                            bool invalid = false;
                                            while ((line.Contains("$HEX[") || line.Contains("$hex[")) && line.Contains("]"))
                                            {
                                                containHexString = true;
                                                line = line.Replace("$HEX[", "");
                                                line = line.Replace("$hex[", "");
                                                line = line.Replace("]", "");
                                                line = line.Replace(" ", "");
                                                line = line.Replace("\0", "");

                                                if (!string.IsNullOrEmpty(line))
                                                {


                                                    byte[] hexBytes = GetByteArrayFromHexString(line);



                                                    if (hexBytes != null)
                                                    {
                                                        hexBytes = hexBytes.TakeWhile((v, index) => hexBytes.Skip(index).Any(w => w != 0x00)).ToArray();

                                                        var encoding = textDetect.DetectEncoding(hexBytes, hexBytes.Length);

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
                                                                                writerBadEncoding.WriteLine(line + " - " + GetHexStringFromByteArray(hexBytes, 0, hexBytes.Length, true));
                                                                            }
                                                                            catch
                                                                            {
                                                                                line = Encoding.GetEncoding(1252).GetString(hexBytes);
                                                                                writerBadEncoding.WriteLine(line + " - " + GetHexStringFromByteArray(hexBytes, 0, hexBytes.Length, true));
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
                                                                                writerBadEncoding.WriteLine(line + " - " + GetHexStringFromByteArray(hexBytes, 0, hexBytes.Length, true));
                                                                            }
                                                                            catch
                                                                            {
                                                                                line = Encoding.GetEncoding(1252).GetString(hexBytes);
                                                                                writerBadEncoding.WriteLine(line + " - " + GetHexStringFromByteArray(hexBytes, 0, hexBytes.Length, true));
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

                                                        if (line.Length >= 4)
                                                        {
                                                            if (!string.IsNullOrEmpty(line))
                                                            {
                                                                if (!line.Contains("$HEX[") && !line.Contains("$hex["))
                                                                {
                                                                    if (CheckWord(line))
                                                                    {
                                                                        if (!IsEmail(line, out bool fixedLine, out string newLine))
                                                                        {
                                                                            if (line.Length > 3)
                                                                            {
                                                                                line = new string(line.Where(c => !char.IsControl(c)).ToArray());

                                                                                if (line.Contains("xCg532%@%gdvf^5DGaa6&*rFTfg^FD4$OIFThrR_gh(ugf*/"))
                                                                                {
                                                                                    line = line.Replace("xCg532%@%gdvf^5DGaa6&*rFTfg^FD4$OIFThrR_gh(ugf*/", "");
                                                                                }

                                                                                if (line.Length == 40 && line.Contains(".") || line.Length == 32)
                                                                                {
                                                                                    if (!_regexHex.IsMatch(line.Substring(0, 32)))
                                                                                    {
                                                                                        if (CheckWord(line))
                                                                                        {
                                                                                            if (!listPass.Contains(line))
                                                                                            {
                                                                                                totalReadLine++;
                                                                                                writer.WriteLine(line);
                                                                                                listPass.Add(line);
                                                                                                if (listPass.Count >= 2000000)
                                                                                                {
                                                                                                    listPass.Clear();
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                                else
                                                                                {
                                                                                    if (!_regexHex.IsMatch(line))
                                                                                    {
                                                                                        if (!listPass.Contains(line))
                                                                                        {
                                                                                            if (CheckWord(line))
                                                                                            {
                                                                                                totalReadLine++;
                                                                                                writer.WriteLine(line);
                                                                                                listPass.Add(line);
                                                                                                if (listPass.Count >= 2000000)
                                                                                                {
                                                                                                    listPass.Clear();
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                        else
                                                                        {
                                                                            if (fixedLine)
                                                                            {
                                                                                if (newLine.Length > 3)
                                                                                {
                                                                                    if (CheckWord(newLine))
                                                                                    {
                                                                                        newLine = new string(newLine.Where(c => !char.IsControl(c)).ToArray());

                                                                                        if (newLine.Contains("xCg532%@%gdvf^5DGaa6&*rFTfg^FD4$OIFThrR_gh(ugf*/"))
                                                                                        {
                                                                                            newLine = newLine.Replace("xCg532%@%gdvf^5DGaa6&*rFTfg^FD4$OIFThrR_gh(ugf*/", "");
                                                                                        }

                                                                                        if (newLine.Length == 40 && newLine.Contains(".") || newLine.Length == 32)
                                                                                        {
                                                                                            if (!_regexHex.IsMatch(newLine.Substring(0, 32)))
                                                                                            {
                                                                                                if (!listPass.Contains(newLine))
                                                                                                {
                                                                                                    totalReadLine++;
                                                                                                    writer.WriteLine(newLine);
                                                                                                    listPass.Add(newLine);
                                                                                                    if (listPass.Count >= 2000000)
                                                                                                    {
                                                                                                        listPass.Clear();
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                        else
                                                                                        {
                                                                                            if (!_regexHex.IsMatch(newLine))
                                                                                            {
                                                                                                if (CheckWord(newLine))
                                                                                                {
                                                                                                    if (!listPass.Contains(newLine))
                                                                                                    {
                                                                                                        totalReadLine++;
                                                                                                        writer.WriteLine(newLine);
                                                                                                        listPass.Add(newLine);
                                                                                                        if (listPass.Count >= 2000000)
                                                                                                        {
                                                                                                            listPass.Clear();
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                            else
                                                                                writerEmail.WriteLine(line);
                                                                        }
                                                                    }
                                                                    else
                                                                        writerInvalid.WriteLine(line);
                                                                    break;
                                                                }
                                                            }
                                                        }
                                                    }
                                                    else
                                                    {
                                                        invalid = true;
                                                        break;
                                                    }
                                                }

                                            }

                                            if (!invalid)
                                            {
                                                if (!containHexString)
                                                {
                                                    if (!string.IsNullOrEmpty(line))
                                                    {
                                                        if (line.Length > 1)
                                                        {
                                                            if (CheckWord(line))
                                                            {
                                                                if (!IsEmail(line, out bool fixedLine, out string newLine))
                                                                {
                                                                    string lineTmp = RemoveControlCharacter(line);

                                                                    if (rewriteLines || lineTmp != line)
                                                                    {
                                                                        if (lineTmp != line)
                                                                        {
                                                                            totalEdited++;
                                                                            writerEdited.WriteLine(lineTmp);
                                                                        }
                                                                        line = lineTmp;
                                                                        if (line.Length > 3)
                                                                        {
                                                                            if (line.Contains("xCg532%@%gdvf^5DGaa6&*rFTfg^FD4$OIFThrR_gh(ugf*/"))
                                                                            {
                                                                                line = line.Replace("xCg532%@%gdvf^5DGaa6&*rFTfg^FD4$OIFThrR_gh(ugf*/", "");
                                                                            }
                                                                            line = RemoveControlCharacter(line);

                                                                            if (line.Length == 40 && line.Contains(".") || line.Length == 32)
                                                                            {
                                                                                if (!_regexHex.IsMatch(line.Substring(0, 32)))
                                                                                {
                                                                                    if (CheckWord(line))
                                                                                    {
                                                                                        if (!listPass.Contains(line))
                                                                                        {
                                                                                            totalReadLine++;
                                                                                            writer.WriteLine(line);
                                                                                            listPass.Add(line);
                                                                                            if (listPass.Count >= 2000000)
                                                                                            {
                                                                                                listPass.Clear();
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                            else
                                                                            {
                                                                                if (!_regexHex.IsMatch(line))
                                                                                {
                                                                                    if (CheckWord(line))
                                                                                    {
                                                                                        if (!listPass.Contains(line))
                                                                                        {
                                                                                            totalReadLine++;
                                                                                            writer.WriteLine(line);
                                                                                            listPass.Add(line);
                                                                                            if (listPass.Count >= 2000000)
                                                                                            {
                                                                                                listPass.Clear();
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }

                                                                }
                                                                else
                                                                {
                                                                    if (fixedLine)
                                                                    {
                                                                        if (newLine.Length > 3)
                                                                        {
                                                                            if (CheckWord(newLine))
                                                                            {
                                                                                newLine = new string(newLine.Where(c => !char.IsControl(c)).ToArray());
                                                                                newLine = RemoveControlCharacter(newLine);

                                                                                if (newLine.Contains("xCg532%@%gdvf^5DGaa6&*rFTfg^FD4$OIFThrR_gh(ugf*/"))
                                                                                {
                                                                                    newLine = newLine.Replace("xCg532%@%gdvf^5DGaa6&*rFTfg^FD4$OIFThrR_gh(ugf*/", "");
                                                                                }

                                                                                if (newLine.Length == 40 && newLine.Contains(".") || newLine.Length == 32)
                                                                                {
                                                                                    if (!_regexHex.IsMatch(newLine.Substring(0, 32)))
                                                                                    {
                                                                                        if (CheckWord(newLine))
                                                                                        {
                                                                                            if (!listPass.Contains(newLine))
                                                                                            {
                                                                                                totalReadLine++;
                                                                                                writer.WriteLine(newLine);
                                                                                                listPass.Add(newLine);
                                                                                                if (listPass.Count >= 2000000)
                                                                                                {
                                                                                                    listPass.Clear();
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                                else
                                                                                {
                                                                                    if (!_regexHex.IsMatch(newLine))
                                                                                    {
                                                                                        if (CheckWord(newLine))
                                                                                        {
                                                                                            if (!listPass.Contains(newLine))
                                                                                            {
                                                                                                totalReadLine++;
                                                                                                writer.WriteLine(newLine);
                                                                                                listPass.Add(newLine);
                                                                                                if (listPass.Count >= 2000000)
                                                                                                {
                                                                                                    listPass.Clear();
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                    else
                                                                    {
                                                                        writerEmail.WriteLine(line);
                                                                    }
                                                                }
                                                            }
                                                            else
                                                            {
                                                                writerInvalid.WriteLine(line);
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                        }
                        else
                        {
                            string line;
                            while ((line = reader.ReadLine()) != null)
                            {
                                line = new string(line.Where(c => !char.IsControl(c)).ToArray());

                                if (line.Contains(":"))
                                {
                                    string[] splitedLine = line.Split(new[] { ":" }, StringSplitOptions.RemoveEmptyEntries);

                                    if (splitedLine.Length >= 2)
                                    {
                                        if (splitedLine[1] != null)
                                        {
                                            if (splitedLine[1] != string.Empty)
                                            {
                                                if (splitedLine[1].Length >= 7)
                                                {
                                                    if (!listPass.Contains(splitedLine[1]))
                                                    {
                                                        listPass.Add(splitedLine[1]);

                                                        if (listPass.Count >= 80_000_000)
                                                        {
                                                            listPass.Clear();
                                                        }

                                                        writer.WriteLine(splitedLine[1]);
                                                        totalEdited++;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    else
                                    {
                                        writerInvalid.WriteLine(line);
                                    }
                                }
                                else
                                {
                                    writerInvalid.WriteLine(line);
                                }
                                totalReadLine++;
                            }
                        }
                    }
                }
            }


            finish = true;

            Console.WriteLine("Processing completed.");
            Console.ReadLine();
        }

        /// <summary>
        /// Merge targeted files into a single file.
        /// </summary>
        private static void MergeFileInOne()
        {
            Console.WriteLine("Enter the path containing the files to merge: ");

            string cheminFichiers = Console.ReadLine();

            Console.WriteLine("Enter the path and name of the final file to save: ");

            string pathFileSave = Console.ReadLine();

            Console.WriteLine("Enter the path of files containing potentially valid lines: ");

            string pathFilePotentialSave = Console.ReadLine();

            string[] files = Directory.GetFiles(cheminFichiers, "*", SearchOption.AllDirectories);

            long totalLineRead = 0;
            long totalLineIgnored = 0;
            int totalFileRead = 0;
            bool finish = false;

            Task.Factory.StartNew(async () =>
            {
                while (!finish)
                {
                    Debug.WriteLine("Total lines read: " + totalLineRead + " from the " + files.Length + " file.");
                    Debug.WriteLine("Total files read: " + totalFileRead + " from the " + files.Length + " file.");
                    Debug.WriteLine("Total lines ignored: "+totalLineIgnored);
                    await Task.Delay(1000);
                }
            }).ConfigureAwait(false);

            bool simpleMerge = false;

            Console.WriteLine("Proceed to a simple merge? [Y/N]");

            simpleMerge = Console.ReadLine()?.ToLower() == "y";

            Console.WriteLine("Merge of " + files.Length + "..");

            UTF8Encoding utf8Encoding = new UTF8Encoding(false);


            Dictionary<string, int> blockDuplicateLines = new Dictionary<string, int>();

            if (!simpleMerge)
            {
                int potentialFileId = 0;
                using (StreamWriter writer = new StreamWriter(pathFileSave, false, utf8Encoding) { AutoFlush = true })
                {

                    using (StreamWriter writerIgnored = new StreamWriter(pathFileSave + "-ignored-file.txt", false, utf8Encoding) { AutoFlush = true })
                    {
                        using (StreamWriter writerIgnoredLine = new StreamWriter(pathFileSave + "-ignored-line.txt", false, utf8Encoding) { AutoFlush = true })
                        {
                            foreach (var file in files)
                            {
                                potentialFileId++;

                                Console.WriteLine("Handle the file " + file + " in pending..");


                                string potentialFile = pathFilePotentialSave + "\\" + potentialFileId + "-potential.txt";
                                long totalPotentialWritten = 0;

                                using (StreamWriter writerPotential = new StreamWriter(potentialFile, false, utf8Encoding) { AutoFlush = true })
                                {
                                    try
                                    {
                                        bool ignored = file.Contains("[HASH]") && (!file.Contains("[NOHASH]") && !file.Contains("[NOTHASH]"));

                                        if (!ignored)
                                        {

                                            using (StreamReader reader = new StreamReader(file))
                                            {
                                                string line;

                                                while ((line = reader.ReadLine()) != null)
                                                {
                                                    if (line.Length > 0 && !string.IsNullOrEmpty(line))
                                                    {

                                                        if (line.Length >= 10240)
                                                        {
                                                            if (line.Contains("\n"))
                                                            {
                                                                foreach (var splitLine in line.Split(new[] { "\n" }, StringSplitOptions.None))
                                                                {
                                                                    if (!string.IsNullOrEmpty(splitLine))
                                                                    {
                                                                        string lineCopy = splitLine;

                                                                        if (lineCopy.Contains("\n"))
                                                                        {
                                                                            foreach (var copyLine in lineCopy.Split(new[] { "\n" }, StringSplitOptions.None))
                                                                            {
                                                                                if (!string.IsNullOrEmpty(copyLine))
                                                                                {
                                                                                    string copy = copyLine;
                                                                                    copy = new string(copy.Where(c => !char.IsControl(c)).ToArray());
                                                                                    copy = RemoveControlCharacter(copy);

                                                                                    if (!string.IsNullOrEmpty(copy))
                                                                                    {
                                                                                        if (copy.Contains("CUT0-"))
                                                                                        {
                                                                                            string[] splitLineCopy = copy.Split(new[] { ":" }, StringSplitOptions.None);
                                                                                            copy = splitLineCopy[2];
                                                                                            writer.WriteLine(copy);
                                                                                        }
                                                                                        else if (copy.StartsWith("MD5SALT"))
                                                                                        {
                                                                                            string newPass = string.Empty;
                                                                                            bool start = false;
                                                                                            foreach (var character in copy)
                                                                                            {
                                                                                                if (!start)
                                                                                                {
                                                                                                    if (character == ':')
                                                                                                    {
                                                                                                        start = true;
                                                                                                    }
                                                                                                }
                                                                                                else
                                                                                                {
                                                                                                    if (character == ':')
                                                                                                    {
                                                                                                        newPass = string.Empty;
                                                                                                    }
                                                                                                    newPass += character;
                                                                                                }
                                                                                            }

                                                                                            copy = newPass;

                                                                                            writer.WriteLine(copy);
                                                                                        }
                                                                                        else
                                                                                        {
                                                                                            bool containDeuxpoints = copy.Contains(":");
                                                                                            bool containPointVirgule = copy.Contains(";");
                                                                                            bool containEspace = copy.Contains(":");
                                                                                            bool containBarre = copy.Contains("|");
                                                                                            bool containTabulation = copy.Contains("\t");

                                                                                            bool resultSplitPass = false;
                                                                                            bool converted = false;
                                                                                            bool ignoreHex = false;
                                                                                            string newLine = string.Empty;

                                                                                            if (containDeuxpoints)
                                                                                            {
                                                                                                resultSplitPass = SplitMergedPassFromEmail(copy, ":", out newLine, out ignoreHex, out converted);
                                                                                            }

                                                                                            if (!ignoreHex)
                                                                                            {
                                                                                                if (resultSplitPass)
                                                                                                {
                                                                                                    if (newLine.Length > 4 || converted)
                                                                                                    {
                                                                                                        if (!blockDuplicateLines.ContainsKey(newLine))
                                                                                                        {
                                                                                                            if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                            {
                                                                                                                blockDuplicateLines.Clear();
                                                                                                            }
                                                                                                            blockDuplicateLines.Add(newLine, 0);
                                                                                                            writer.WriteLine(newLine);
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                                else
                                                                                                {
                                                                                                    if (containPointVirgule)
                                                                                                    {
                                                                                                        resultSplitPass = SplitMergedPassFromEmail(copy, ";", out newLine, out ignoreHex, out converted);
                                                                                                    }

                                                                                                    if (!ignoreHex)
                                                                                                    {
                                                                                                        if (resultSplitPass)
                                                                                                        {
                                                                                                            if (newLine.Length > 4 || converted)
                                                                                                            {
                                                                                                                writer.WriteLine(newLine);
                                                                                                            }
                                                                                                        }
                                                                                                        else
                                                                                                        {
                                                                                                            if (containBarre)
                                                                                                            {
                                                                                                                resultSplitPass = SplitMergedPassFromEmail(copy, "|", out newLine, out ignoreHex, out converted);
                                                                                                            }

                                                                                                            if (!ignoreHex)
                                                                                                            {
                                                                                                                if (resultSplitPass)
                                                                                                                {
                                                                                                                    if (newLine.Length > 4 || converted)
                                                                                                                    {
                                                                                                                        if (!blockDuplicateLines.ContainsKey(newLine))
                                                                                                                        {
                                                                                                                            if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                                            {
                                                                                                                                blockDuplicateLines.Clear();
                                                                                                                            }
                                                                                                                            blockDuplicateLines.Add(newLine, 0);
                                                                                                                            writer.WriteLine(newLine);
                                                                                                                        }
                                                                                                                    }
                                                                                                                }
                                                                                                                else
                                                                                                                {
                                                                                                                    if (containTabulation)
                                                                                                                    {
                                                                                                                        resultSplitPass = SplitMergedPassFromEmail(copy, "\t", out newLine, out ignoreHex, out converted);
                                                                                                                    }

                                                                                                                    if (!ignoreHex)
                                                                                                                    {
                                                                                                                        if (resultSplitPass)
                                                                                                                        {
                                                                                                                            if (newLine.Length > 4 || converted)
                                                                                                                            {
                                                                                                                                if (!blockDuplicateLines.ContainsKey(newLine))
                                                                                                                                {
                                                                                                                                    if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                                                    {
                                                                                                                                        blockDuplicateLines.Clear();
                                                                                                                                    }
                                                                                                                                    blockDuplicateLines.Add(newLine, 0);
                                                                                                                                    writer.WriteLine(newLine);
                                                                                                                                }
                                                                                                                            }
                                                                                                                        }
                                                                                                                        else
                                                                                                                        {
                                                                                                                            if (containEspace)
                                                                                                                            {
                                                                                                                                resultSplitPass = SplitMergedPassFromEmail(copy, " ", out newLine, out ignoreHex, out converted);
                                                                                                                            }

                                                                                                                            if (!ignoreHex)
                                                                                                                            {
                                                                                                                                if (resultSplitPass)
                                                                                                                                {
                                                                                                                                    if (newLine.Length > 4 || converted)
                                                                                                                                    {
                                                                                                                                        if (!blockDuplicateLines.ContainsKey(newLine))
                                                                                                                                        {
                                                                                                                                            if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                                                            {
                                                                                                                                                blockDuplicateLines.Clear();
                                                                                                                                            }
                                                                                                                                            blockDuplicateLines.Add(newLine, 0);
                                                                                                                                            writer.WriteLine(newLine);
                                                                                                                                        }
                                                                                                                                    }
                                                                                                                                }
                                                                                                                                else
                                                                                                                                {
                                                                                                                                    if (copy.Length > 4)
                                                                                                                                    {
                                                                                                                                        if (!_regexEmail.IsMatch(copy))
                                                                                                                                        {
                                                                                                                                            bool valid = false;

                                                                                                                                            if (copy.Contains(";"))
                                                                                                                                            {
                                                                                                                                                var splitCopy = copy.Split(new[] { ";" }, StringSplitOptions.None);
                                                                                                                                                if (splitCopy.Length == 2)
                                                                                                                                                {
                                                                                                                                                    if (!(_regexHex.IsMatch(splitCopy[1]) && splitCopy[1].Length == 32))
                                                                                                                                                    {
                                                                                                                                                        if (!_regexEmail.IsMatch(splitCopy[1]))
                                                                                                                                                        {
                                                                                                                                                            if (splitCopy[1].Length > 4)
                                                                                                                                                            {
                                                                                                                                                                valid = true;

                                                                                                                                                                if (!blockDuplicateLines.ContainsKey(splitCopy[1]))
                                                                                                                                                                {
                                                                                                                                                                    if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                                                                                    {
                                                                                                                                                                        blockDuplicateLines.Clear();
                                                                                                                                                                    }
                                                                                                                                                                    blockDuplicateLines.Add(splitCopy[1], 0);
                                                                                                                                                                    writer.WriteLine(splitCopy[1]);
                                                                                                                                                                }
                                                                                                                                                            }
                                                                                                                                                        }
                                                                                                                                                    }

                                                                                                                                                    if (!(_regexHex.IsMatch(splitCopy[0]) && splitCopy[0].Length == 32))
                                                                                                                                                    {
                                                                                                                                                        if (!_regexEmail.IsMatch(splitCopy[0]))
                                                                                                                                                        {
                                                                                                                                                            if (splitCopy[0].Length > 4)
                                                                                                                                                            {
                                                                                                                                                                valid = true;

                                                                                                                                                                if (!blockDuplicateLines.ContainsKey(splitCopy[0]))
                                                                                                                                                                {
                                                                                                                                                                    if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                                                                                    {
                                                                                                                                                                        blockDuplicateLines.Clear();
                                                                                                                                                                    }
                                                                                                                                                                    blockDuplicateLines.Add(splitCopy[0], 0);
                                                                                                                                                                    writer.WriteLine(splitCopy[0]);
                                                                                                                                                                }
                                                                                                                                                            }
                                                                                                                                                        }
                                                                                                                                                    }
                                                                                                                                                }
                                                                                                                                            }

                                                                                                                                            if (copy.Contains(":"))
                                                                                                                                            {
                                                                                                                                                var splitCopy = copy.Split(new[] { ":" }, StringSplitOptions.None);
                                                                                                                                                if (splitCopy.Length == 2)
                                                                                                                                                {
                                                                                                                                                    if (!(_regexHex.IsMatch(splitCopy[1]) && splitCopy[1].Length == 32))
                                                                                                                                                    {
                                                                                                                                                        if (!_regexEmail.IsMatch(splitCopy[1]))
                                                                                                                                                        {
                                                                                                                                                            if (splitCopy[1].Length > 4)
                                                                                                                                                            {
                                                                                                                                                                valid = true;

                                                                                                                                                                if (!blockDuplicateLines.ContainsKey(splitCopy[1]))
                                                                                                                                                                {
                                                                                                                                                                    if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                                                                                    {
                                                                                                                                                                        blockDuplicateLines.Clear();
                                                                                                                                                                    }
                                                                                                                                                                    blockDuplicateLines.Add(splitCopy[1], 0);
                                                                                                                                                                    writer.WriteLine(splitCopy[1]);
                                                                                                                                                                }
                                                                                                                                                            }
                                                                                                                                                        }
                                                                                                                                                    }

                                                                                                                                                    if (!(_regexHex.IsMatch(splitCopy[0]) && splitCopy[0].Length == 32))
                                                                                                                                                    {
                                                                                                                                                        if (!_regexEmail.IsMatch(splitCopy[0]))
                                                                                                                                                        {
                                                                                                                                                            if (splitCopy[0].Length > 4)
                                                                                                                                                            {
                                                                                                                                                                valid = true;

                                                                                                                                                                if (!blockDuplicateLines.ContainsKey(splitCopy[0]))
                                                                                                                                                                {
                                                                                                                                                                    if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                                                                                    {
                                                                                                                                                                        blockDuplicateLines.Clear();
                                                                                                                                                                    }
                                                                                                                                                                    blockDuplicateLines.Add(splitCopy[0], 0);
                                                                                                                                                                    writer.WriteLine(splitCopy[0]);
                                                                                                                                                                }
                                                                                                                                                            }
                                                                                                                                                        }
                                                                                                                                                    }
                                                                                                                                                }
                                                                                                                                            }

                                                                                                                                            if (!valid)
                                                                                                                                            {
                                                                                                                                                writerPotential.WriteLine(copy);
                                                                                                                                                totalPotentialWritten++;
                                                                                                                                            }
                                                                                                                                        }
                                                                                                                                        else
                                                                                                                                        {
                                                                                                                                            ignoreHex = true;
                                                                                                                                        }
                                                                                                                                    }

                                                                                                                                    //Debug.WriteLine("Can't found seperator on line: " + line);

                                                                                                                                }
                                                                                                                            }
                                                                                                                        }
                                                                                                                    }
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }

                                                                                            if (ignoreHex)
                                                                                            {
                                                                                                totalLineIgnored++;
                                                                                                writerIgnoredLine.WriteLine(file + " ->" + line);
                                                                                            }
                                                                                        }
                                                                                    }

                                                                                }
                                                                            }
                                                                        }
                                                                        else
                                                                        {

                                                                            lineCopy = new string(lineCopy.Where(c => !char.IsControl(c)).ToArray());
                                                                            lineCopy = RemoveControlCharacter(lineCopy);
                                                                            if (!string.IsNullOrEmpty(lineCopy))
                                                                            {
                                                                                if (line.Contains("CUT0-"))
                                                                                {
                                                                                    string[] splitLineCopy = lineCopy.Split(new[] { ":" }, StringSplitOptions.None);
                                                                                    lineCopy = splitLineCopy[2];
                                                                                    writer.WriteLine(lineCopy);
                                                                                }
                                                                                else if (lineCopy.StartsWith("MD5SALT"))
                                                                                {
                                                                                    string newPass = string.Empty;
                                                                                    bool start = false;
                                                                                    foreach (var character in lineCopy)
                                                                                    {
                                                                                        if (!start)
                                                                                        {
                                                                                            if (character == ':')
                                                                                            {
                                                                                                start = true;
                                                                                            }
                                                                                        }
                                                                                        else
                                                                                        {
                                                                                            if (character == ':')
                                                                                            {
                                                                                                newPass = string.Empty;
                                                                                            }
                                                                                            newPass += character;
                                                                                        }
                                                                                    }


                                                                                    lineCopy = newPass;

                                                                                    writer.WriteLine(lineCopy);
                                                                                }
                                                                                else
                                                                                {

                                                                                    var resultSplitPass = SplitMergedPassFromEmail(lineCopy, ":", out var newLine, out var ignoreHex, out var converted);

                                                                                    if (!ignoreHex)
                                                                                    {
                                                                                        if (resultSplitPass)
                                                                                        {
                                                                                            if (newLine.Length > 4 || converted)
                                                                                            {
                                                                                                if (!blockDuplicateLines.ContainsKey(newLine))
                                                                                                {
                                                                                                    if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                    {
                                                                                                        blockDuplicateLines.Clear();
                                                                                                    }
                                                                                                    blockDuplicateLines.Add(newLine, 0);
                                                                                                    writer.WriteLine(newLine);
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                        else
                                                                                        {
                                                                                            resultSplitPass = SplitMergedPassFromEmail(lineCopy, ";", out newLine, out ignoreHex, out converted);

                                                                                            if (!ignoreHex)
                                                                                            {
                                                                                                if (resultSplitPass)
                                                                                                {
                                                                                                    if (newLine.Length > 4 || converted)
                                                                                                    {
                                                                                                        writer.WriteLine(newLine);
                                                                                                    }
                                                                                                }
                                                                                                else
                                                                                                {
                                                                                                    resultSplitPass = SplitMergedPassFromEmail(lineCopy, "|", out newLine, out ignoreHex, out converted);

                                                                                                    if (!ignoreHex)
                                                                                                    {
                                                                                                        if (resultSplitPass)
                                                                                                        {
                                                                                                            if (newLine.Length > 4 || converted)
                                                                                                            {
                                                                                                                if (!blockDuplicateLines.ContainsKey(newLine))
                                                                                                                {
                                                                                                                    if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                                    {
                                                                                                                        blockDuplicateLines.Clear();
                                                                                                                    }
                                                                                                                    blockDuplicateLines.Add(newLine, 0);
                                                                                                                    writer.WriteLine(newLine);
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                        else
                                                                                                        {
                                                                                                            resultSplitPass = SplitMergedPassFromEmail(lineCopy, "\t", out newLine, out ignoreHex, out converted);

                                                                                                            if (!ignoreHex)
                                                                                                            {
                                                                                                                if (resultSplitPass)
                                                                                                                {
                                                                                                                    if (newLine.Length > 4 || converted)
                                                                                                                    {
                                                                                                                        if (!blockDuplicateLines.ContainsKey(newLine))
                                                                                                                        {
                                                                                                                            if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                                            {
                                                                                                                                blockDuplicateLines.Clear();
                                                                                                                            }
                                                                                                                            blockDuplicateLines.Add(newLine, 0);
                                                                                                                            writer.WriteLine(newLine);
                                                                                                                        }
                                                                                                                    }
                                                                                                                }
                                                                                                                else
                                                                                                                {
                                                                                                                    resultSplitPass = SplitMergedPassFromEmail(lineCopy, " ", out newLine, out ignoreHex, out converted);

                                                                                                                    if (!ignoreHex)
                                                                                                                    {
                                                                                                                        if (resultSplitPass)
                                                                                                                        {
                                                                                                                            if (newLine.Length > 4 || converted)
                                                                                                                            {
                                                                                                                                if (!blockDuplicateLines.ContainsKey(newLine))
                                                                                                                                {
                                                                                                                                    if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                                                    {
                                                                                                                                        blockDuplicateLines.Clear();
                                                                                                                                    }
                                                                                                                                    blockDuplicateLines.Add(newLine, 0);
                                                                                                                                    writer.WriteLine(newLine);
                                                                                                                                }
                                                                                                                            }
                                                                                                                        }
                                                                                                                        else
                                                                                                                        {
                                                                                                                            if (line.Length > 4)
                                                                                                                            {
                                                                                                                                if (!_regexEmail.IsMatch(lineCopy))
                                                                                                                                {
                                                                                                                                    bool valid = false;

                                                                                                                                    if (lineCopy.Contains(";"))
                                                                                                                                    {
                                                                                                                                        var splitCopy = lineCopy.Split(new[] { ";" }, StringSplitOptions.None);
                                                                                                                                        if (splitCopy.Length == 2)
                                                                                                                                        {
                                                                                                                                            if (!(_regexHex.IsMatch(splitCopy[1]) && splitCopy[1].Length == 32))
                                                                                                                                            {
                                                                                                                                                if (!_regexEmail.IsMatch(splitCopy[1]))
                                                                                                                                                {
                                                                                                                                                    if (splitCopy[1].Length > 4)
                                                                                                                                                    {
                                                                                                                                                        valid = true;
                                                                                                                                                        if (!blockDuplicateLines.ContainsKey(splitCopy[1]))
                                                                                                                                                        {
                                                                                                                                                            if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                                                                            {
                                                                                                                                                                blockDuplicateLines.Clear();
                                                                                                                                                            }
                                                                                                                                                            blockDuplicateLines.Add(splitCopy[1], 0);
                                                                                                                                                            writer.WriteLine(splitCopy[1]);
                                                                                                                                                        }
                                                                                                                                                    }
                                                                                                                                                }
                                                                                                                                            }

                                                                                                                                            if (!(_regexHex.IsMatch(splitCopy[0]) && splitCopy[0].Length == 32))
                                                                                                                                            {
                                                                                                                                                if (!_regexEmail.IsMatch(splitCopy[0]))
                                                                                                                                                {
                                                                                                                                                    if (splitCopy[0].Length > 4)
                                                                                                                                                    {
                                                                                                                                                        valid = true;

                                                                                                                                                        if (!blockDuplicateLines.ContainsKey(splitCopy[0]))
                                                                                                                                                        {
                                                                                                                                                            if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                                                                            {
                                                                                                                                                                blockDuplicateLines.Clear();
                                                                                                                                                            }
                                                                                                                                                            blockDuplicateLines.Add(splitCopy[0], 0);
                                                                                                                                                            writer.WriteLine(splitCopy[0]);
                                                                                                                                                        }
                                                                                                                                                    }
                                                                                                                                                }
                                                                                                                                            }
                                                                                                                                        }
                                                                                                                                    }

                                                                                                                                    if (lineCopy.Contains(":"))
                                                                                                                                    {
                                                                                                                                        var splitCopy = lineCopy.Split(new[] { ":" }, StringSplitOptions.None);
                                                                                                                                        if (splitCopy.Length == 2)
                                                                                                                                        {
                                                                                                                                            if (!(_regexHex.IsMatch(splitCopy[1]) && splitCopy[1].Length == 32))
                                                                                                                                            {
                                                                                                                                                if (!_regexEmail.IsMatch(splitCopy[1]))
                                                                                                                                                {
                                                                                                                                                    if (splitCopy[1].Length > 4)
                                                                                                                                                    {
                                                                                                                                                        valid = true;

                                                                                                                                                        if (!blockDuplicateLines.ContainsKey(splitCopy[1]))
                                                                                                                                                        {
                                                                                                                                                            if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                                                                            {
                                                                                                                                                                blockDuplicateLines.Clear();
                                                                                                                                                            }
                                                                                                                                                            blockDuplicateLines.Add(splitCopy[1], 0);
                                                                                                                                                            writer.WriteLine(splitCopy[1]);
                                                                                                                                                        }
                                                                                                                                                    }
                                                                                                                                                }
                                                                                                                                            }

                                                                                                                                            if (!(_regexHex.IsMatch(splitCopy[0]) && splitCopy[0].Length == 32))
                                                                                                                                            {
                                                                                                                                                if (!_regexEmail.IsMatch(splitCopy[0]))
                                                                                                                                                {
                                                                                                                                                    if (splitCopy[0].Length > 4)
                                                                                                                                                    {
                                                                                                                                                        valid = true;

                                                                                                                                                        if (!blockDuplicateLines.ContainsKey(splitCopy[0]))
                                                                                                                                                        {
                                                                                                                                                            if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                                                                            {
                                                                                                                                                                blockDuplicateLines.Clear();
                                                                                                                                                            }
                                                                                                                                                            blockDuplicateLines.Add(splitCopy[0], 0);
                                                                                                                                                            writer.WriteLine(splitCopy[0]);
                                                                                                                                                        }
                                                                                                                                                    }
                                                                                                                                                }
                                                                                                                                            }
                                                                                                                                        }
                                                                                                                                    }


                                                                                                                                    if (!valid)
                                                                                                                                    {
                                                                                                                                        writerPotential.WriteLine(lineCopy);
                                                                                                                                        totalPotentialWritten++;
                                                                                                                                    }

                                                                                                                                }
                                                                                                                                else
                                                                                                                                {
                                                                                                                                    ignoreHex = true;
                                                                                                                                }
                                                                                                                            }

                                                                                                                            //Debug.WriteLine("Can't found seperator on line: " + line);

                                                                                                                        }
                                                                                                                    }
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }

                                                                                    if (ignoreHex)
                                                                                    {
                                                                                        if (line.Length > 4)
                                                                                        {
                                                                                            if (!_regexEmail.IsMatch(lineCopy))
                                                                                            {
                                                                                                bool valid = false;

                                                                                                if (lineCopy.Contains(";"))
                                                                                                {
                                                                                                    var splitCopy = lineCopy.Split(new[] { ";" }, StringSplitOptions.None);
                                                                                                    if (splitCopy.Length == 2)
                                                                                                    {
                                                                                                        if (!(_regexHex.IsMatch(splitCopy[1]) && splitCopy[1].Length == 32))
                                                                                                        {
                                                                                                            if (!_regexEmail.IsMatch(splitCopy[1]))
                                                                                                            {
                                                                                                                if (splitCopy[1].Length > 4)
                                                                                                                {
                                                                                                                    valid = true;
                                                                                                                    if (!blockDuplicateLines.ContainsKey(splitCopy[1]))
                                                                                                                    {
                                                                                                                        if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                                        {
                                                                                                                            blockDuplicateLines.Clear();
                                                                                                                        }
                                                                                                                        blockDuplicateLines.Add(splitCopy[1], 0);
                                                                                                                        writer.WriteLine(splitCopy[1]);
                                                                                                                    }
                                                                                                                }
                                                                                                            }
                                                                                                        }

                                                                                                        if (!(_regexHex.IsMatch(splitCopy[0]) && splitCopy[0].Length == 32))
                                                                                                        {
                                                                                                            if (!_regexEmail.IsMatch(splitCopy[0]))
                                                                                                            {
                                                                                                                if (splitCopy[0].Length > 4)
                                                                                                                {
                                                                                                                    valid = true;

                                                                                                                    if (!blockDuplicateLines.ContainsKey(splitCopy[0]))
                                                                                                                    {
                                                                                                                        if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                                        {
                                                                                                                            blockDuplicateLines.Clear();
                                                                                                                        }
                                                                                                                        blockDuplicateLines.Add(splitCopy[0], 0);
                                                                                                                        writer.WriteLine(splitCopy[0]);
                                                                                                                    }
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }

                                                                                                if (lineCopy.Contains(":"))
                                                                                                {
                                                                                                    var splitCopy = lineCopy.Split(new[] { ":" }, StringSplitOptions.None);
                                                                                                    if (splitCopy.Length == 2)
                                                                                                    {
                                                                                                        if (!(_regexHex.IsMatch(splitCopy[1]) && splitCopy[1].Length == 32))
                                                                                                        {
                                                                                                            if (!_regexEmail.IsMatch(splitCopy[1]))
                                                                                                            {
                                                                                                                if (splitCopy[1].Length > 4)
                                                                                                                {
                                                                                                                    valid = true;

                                                                                                                    if (!blockDuplicateLines.ContainsKey(splitCopy[1]))
                                                                                                                    {
                                                                                                                        if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                                        {
                                                                                                                            blockDuplicateLines.Clear();
                                                                                                                        }
                                                                                                                        blockDuplicateLines.Add(splitCopy[1], 0);
                                                                                                                        writer.WriteLine(splitCopy[1]);
                                                                                                                    }
                                                                                                                }
                                                                                                            }
                                                                                                        }

                                                                                                        if (!(_regexHex.IsMatch(splitCopy[0]) && splitCopy[0].Length == 32))
                                                                                                        {
                                                                                                            if (!_regexEmail.IsMatch(splitCopy[0]))
                                                                                                            {
                                                                                                                if (splitCopy[0].Length > 4)
                                                                                                                {
                                                                                                                    valid = true;

                                                                                                                    if (!blockDuplicateLines.ContainsKey(splitCopy[0]))
                                                                                                                    {
                                                                                                                        if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                                        {
                                                                                                                            blockDuplicateLines.Clear();
                                                                                                                        }
                                                                                                                        blockDuplicateLines.Add(splitCopy[0], 0);
                                                                                                                        writer.WriteLine(splitCopy[0]);
                                                                                                                    }
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                    }
                                                                                                }


                                                                                                if (!valid)
                                                                                                {
                                                                                                    totalLineIgnored++;
                                                                                                    writerIgnoredLine.WriteLine(file + " ->" + line);
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                        else
                                                        {
                                                            line = new string(line.Where(c => !char.IsControl(c)).ToArray());
                                                            line = RemoveControlCharacter(line);
                                                            if (!string.IsNullOrEmpty(line))
                                                            {
                                                                if (line.Contains("CUT0-"))
                                                                {
                                                                    string[] splitLine = line.Split(new[] { ":" }, StringSplitOptions.None);
                                                                    line = splitLine[2];
                                                                    writer.WriteLine(line);
                                                                }
                                                                else if (line.StartsWith("MD5SALT"))
                                                                {
                                                                    string newPass = string.Empty;
                                                                    bool start = false;
                                                                    foreach (var character in line)
                                                                    {
                                                                        if (!start)
                                                                        {
                                                                            if (character == ':')
                                                                            {
                                                                                start = true;
                                                                            }
                                                                        }
                                                                        else
                                                                        {
                                                                            if (character == ':')
                                                                            {
                                                                                newPass = string.Empty;
                                                                            }
                                                                            newPass += character;
                                                                        }
                                                                    }

                                                                    line = newPass;

                                                                    writer.WriteLine(line);
                                                                }
                                                                else
                                                                {
                                                                    bool containDeuxpoints = line.Contains(":");
                                                                    bool containPointVirgule = line.Contains(";");
                                                                    bool containEspace = line.Contains(":");
                                                                    bool containBarre = line.Contains("|");
                                                                    bool containTabulation = line.Contains("\t");

                                                                    bool resultSplitPass = false;
                                                                    bool converted = false;
                                                                    bool ignoreHex = false;
                                                                    string newLine = string.Empty;

                                                                    if (containDeuxpoints)
                                                                    {
                                                                        resultSplitPass = SplitMergedPassFromEmail(line, ":", out newLine, out ignoreHex, out converted);
                                                                    }

                                                                    if (!ignoreHex)
                                                                    {
                                                                        if (resultSplitPass)
                                                                        {
                                                                            if (newLine.Length > 4 || converted)
                                                                            {
                                                                                if (!blockDuplicateLines.ContainsKey(newLine))
                                                                                {
                                                                                    if (blockDuplicateLines.Count >= 80_000_000)
                                                                                    {
                                                                                        blockDuplicateLines.Clear();
                                                                                    }
                                                                                    blockDuplicateLines.Add(newLine, 0);
                                                                                    writer.WriteLine(newLine);
                                                                                }
                                                                            }
                                                                        }
                                                                        else
                                                                        {
                                                                            if (containPointVirgule)
                                                                            {
                                                                                resultSplitPass = SplitMergedPassFromEmail(line, ";", out newLine, out ignoreHex, out converted);
                                                                            }

                                                                            if (!ignoreHex)
                                                                            {
                                                                                if (resultSplitPass)
                                                                                {
                                                                                    if (newLine.Length > 4 || converted)
                                                                                    {
                                                                                        if (!blockDuplicateLines.ContainsKey(newLine))
                                                                                        {
                                                                                            if (blockDuplicateLines.Count >= 80_000_000)
                                                                                            {
                                                                                                blockDuplicateLines.Clear();
                                                                                            }
                                                                                            blockDuplicateLines.Add(newLine, 0);
                                                                                            writer.WriteLine(newLine);
                                                                                        }
                                                                                    }
                                                                                }
                                                                                else
                                                                                {
                                                                                    if (containBarre)
                                                                                    {
                                                                                        resultSplitPass = SplitMergedPassFromEmail(line, "|", out newLine, out ignoreHex, out converted);
                                                                                    }

                                                                                    if (!ignoreHex)
                                                                                    {
                                                                                        if (resultSplitPass)
                                                                                        {
                                                                                            if (newLine.Length > 4 || converted)
                                                                                            {
                                                                                                if (!blockDuplicateLines.ContainsKey(newLine))
                                                                                                {
                                                                                                    if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                    {
                                                                                                        blockDuplicateLines.Clear();
                                                                                                    }
                                                                                                    blockDuplicateLines.Add(newLine, 0);
                                                                                                    writer.WriteLine(newLine);
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                        else
                                                                                        {
                                                                                            if (containTabulation)
                                                                                            {
                                                                                                resultSplitPass = SplitMergedPassFromEmail(line, "\t", out newLine, out ignoreHex, out converted);
                                                                                            }

                                                                                            if (!ignoreHex)
                                                                                            {
                                                                                                if (resultSplitPass)
                                                                                                {
                                                                                                    if (newLine.Length > 4 || converted)
                                                                                                    {
                                                                                                        if (!blockDuplicateLines.ContainsKey(newLine))
                                                                                                        {
                                                                                                            if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                            {
                                                                                                                blockDuplicateLines.Clear();
                                                                                                            }
                                                                                                            blockDuplicateLines.Add(newLine, 0);
                                                                                                            writer.WriteLine(newLine);
                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                                else
                                                                                                {
                                                                                                    if (containEspace)
                                                                                                    {
                                                                                                        resultSplitPass = SplitMergedPassFromEmail(line, " ", out newLine, out ignoreHex, out converted);
                                                                                                    }

                                                                                                    if (!ignoreHex)
                                                                                                    {
                                                                                                        if (resultSplitPass)
                                                                                                        {
                                                                                                            if (newLine.Length > 4 || converted)
                                                                                                            {
                                                                                                                if (!blockDuplicateLines.ContainsKey(newLine))
                                                                                                                {
                                                                                                                    if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                                    {
                                                                                                                        blockDuplicateLines.Clear();
                                                                                                                    }
                                                                                                                    blockDuplicateLines.Add(newLine, 0);
                                                                                                                    writer.WriteLine(newLine);
                                                                                                                }
                                                                                                            }
                                                                                                        }
                                                                                                        else
                                                                                                        {
                                                                                                            if (line.Length > 4)
                                                                                                            {
                                                                                                                if (!_regexEmail.IsMatch(line))
                                                                                                                {
                                                                                                                    bool valid = false;
                                                                                                                    if (line.Contains(";"))
                                                                                                                    {
                                                                                                                        var splitCopy = line.Split(new[] { ";" }, StringSplitOptions.None);
                                                                                                                        if (splitCopy.Length == 2)
                                                                                                                        {
                                                                                                                            if (!(_regexHex.IsMatch(splitCopy[1]) && splitCopy[1].Length == 32))
                                                                                                                            {
                                                                                                                                if (!_regexEmail.IsMatch(splitCopy[1]))
                                                                                                                                {
                                                                                                                                    if (splitCopy[1].Length > 4)
                                                                                                                                    {
                                                                                                                                        valid = true;
                                                                                                                                        if (!blockDuplicateLines.ContainsKey(splitCopy[1]))
                                                                                                                                        {
                                                                                                                                            if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                                                            {
                                                                                                                                                blockDuplicateLines.Clear();
                                                                                                                                            }
                                                                                                                                            blockDuplicateLines.Add(splitCopy[1], 0);
                                                                                                                                            writer.WriteLine(splitCopy[1]);
                                                                                                                                        }
                                                                                                                                    }
                                                                                                                                }
                                                                                                                            }

                                                                                                                            if (!(_regexHex.IsMatch(splitCopy[0]) && splitCopy[0].Length == 32))
                                                                                                                            {
                                                                                                                                if (!_regexEmail.IsMatch(splitCopy[0]))
                                                                                                                                {
                                                                                                                                    if (splitCopy[0].Length > 4)
                                                                                                                                    {
                                                                                                                                        valid = true;
                                                                                                                                        if (!blockDuplicateLines.ContainsKey(splitCopy[0]))
                                                                                                                                        {
                                                                                                                                            if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                                                            {
                                                                                                                                                blockDuplicateLines.Clear();
                                                                                                                                            }
                                                                                                                                            blockDuplicateLines.Add(splitCopy[0], 0);
                                                                                                                                            writer.WriteLine(splitCopy[0]);
                                                                                                                                        }
                                                                                                                                    }
                                                                                                                                }
                                                                                                                            }
                                                                                                                        }
                                                                                                                    }

                                                                                                                    if (line.Contains(":"))
                                                                                                                    {
                                                                                                                        var splitCopy = line.Split(new[] { ":" }, StringSplitOptions.None);
                                                                                                                        if (splitCopy.Length == 2)
                                                                                                                        {
                                                                                                                            if (!(_regexHex.IsMatch(splitCopy[1]) && splitCopy[1].Length == 32))
                                                                                                                            {
                                                                                                                                if (!_regexEmail.IsMatch(splitCopy[1]))
                                                                                                                                {
                                                                                                                                    if (splitCopy[1].Length > 4)
                                                                                                                                    {
                                                                                                                                        valid = true;

                                                                                                                                        if (!blockDuplicateLines.ContainsKey(splitCopy[1]))
                                                                                                                                        {
                                                                                                                                            if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                                                            {
                                                                                                                                                blockDuplicateLines.Clear();
                                                                                                                                            }
                                                                                                                                            blockDuplicateLines.Add(splitCopy[1], 0);
                                                                                                                                            writer.WriteLine(splitCopy[1]);
                                                                                                                                        }
                                                                                                                                    }
                                                                                                                                }
                                                                                                                            }

                                                                                                                            if (!(_regexHex.IsMatch(splitCopy[0]) && splitCopy[0].Length == 32))
                                                                                                                            {
                                                                                                                                if (!_regexEmail.IsMatch(splitCopy[0]))
                                                                                                                                {
                                                                                                                                    if (splitCopy[0].Length > 4)
                                                                                                                                    {
                                                                                                                                        valid = true;

                                                                                                                                        if (!blockDuplicateLines.ContainsKey(splitCopy[0]))
                                                                                                                                        {
                                                                                                                                            if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                                                            {
                                                                                                                                                blockDuplicateLines.Clear();
                                                                                                                                            }
                                                                                                                                            blockDuplicateLines.Add(splitCopy[0], 0);
                                                                                                                                            writer.WriteLine(splitCopy[0]);
                                                                                                                                        }
                                                                                                                                    }
                                                                                                                                }
                                                                                                                            }
                                                                                                                        }
                                                                                                                    }


                                                                                                                    if (!valid)
                                                                                                                    {
                                                                                                                        writerPotential.WriteLine(line);
                                                                                                                        totalPotentialWritten++;

                                                                                                                    }

                                                                                                                }
                                                                                                                else
                                                                                                                {
                                                                                                                    ignoreHex = true;
                                                                                                                }
                                                                                                            }

                                                                                                            //Debug.WriteLine("Can't found seperator on line: " + line);

                                                                                                        }
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }
                                                                            }
                                                                        }
                                                                    }

                                                                    if (ignoreHex)
                                                                    {
                                                                        if (line.Length > 4)
                                                                        {
                                                                            if (!_regexEmail.IsMatch(line))
                                                                            {
                                                                                bool valid = false;
                                                                                if (line.Contains(";"))
                                                                                {
                                                                                    var splitCopy = line.Split(new[] { ";" }, StringSplitOptions.None);
                                                                                    if (splitCopy.Length == 2)
                                                                                    {
                                                                                        if (!(_regexHex.IsMatch(splitCopy[1]) && splitCopy[1].Length == 32))
                                                                                        {
                                                                                            if (!_regexEmail.IsMatch(splitCopy[1]))
                                                                                            {
                                                                                                if (splitCopy[1].Length > 4)
                                                                                                {
                                                                                                    valid = true;
                                                                                                    if (!blockDuplicateLines.ContainsKey(splitCopy[1]))
                                                                                                    {
                                                                                                        if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                        {
                                                                                                            blockDuplicateLines.Clear();
                                                                                                        }
                                                                                                        blockDuplicateLines.Add(splitCopy[1], 0);
                                                                                                        writer.WriteLine(splitCopy[1]);
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }

                                                                                        if (!(_regexHex.IsMatch(splitCopy[0]) && splitCopy[0].Length == 32))
                                                                                        {
                                                                                            if (!_regexEmail.IsMatch(splitCopy[0]))
                                                                                            {
                                                                                                if (splitCopy[0].Length > 4)
                                                                                                {
                                                                                                    valid = true;
                                                                                                    if (!blockDuplicateLines.ContainsKey(splitCopy[0]))
                                                                                                    {
                                                                                                        if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                        {
                                                                                                            blockDuplicateLines.Clear();
                                                                                                        }
                                                                                                        blockDuplicateLines.Add(splitCopy[0], 0);
                                                                                                        writer.WriteLine(splitCopy[0]);
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }

                                                                                if (line.Contains(":"))
                                                                                {
                                                                                    var splitCopy = line.Split(new[] { ":" }, StringSplitOptions.None);
                                                                                    if (splitCopy.Length == 2)
                                                                                    {
                                                                                        if (!(_regexHex.IsMatch(splitCopy[1]) && splitCopy[1].Length == 32))
                                                                                        {
                                                                                            if (!_regexEmail.IsMatch(splitCopy[1]))
                                                                                            {
                                                                                                if (splitCopy[1].Length > 4)
                                                                                                {
                                                                                                    valid = true;

                                                                                                    if (!blockDuplicateLines.ContainsKey(splitCopy[1]))
                                                                                                    {
                                                                                                        if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                        {
                                                                                                            blockDuplicateLines.Clear();
                                                                                                        }
                                                                                                        blockDuplicateLines.Add(splitCopy[1], 0);
                                                                                                        writer.WriteLine(splitCopy[1]);
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }

                                                                                        if (!(_regexHex.IsMatch(splitCopy[0]) && splitCopy[0].Length == 32))
                                                                                        {
                                                                                            if (!_regexEmail.IsMatch(splitCopy[0]))
                                                                                            {
                                                                                                if (splitCopy[0].Length > 4)
                                                                                                {
                                                                                                    valid = true;

                                                                                                    if (!blockDuplicateLines.ContainsKey(splitCopy[0]))
                                                                                                    {
                                                                                                        if (blockDuplicateLines.Count >= 80_000_000)
                                                                                                        {
                                                                                                            blockDuplicateLines.Clear();
                                                                                                        }
                                                                                                        blockDuplicateLines.Add(splitCopy[0], 0);
                                                                                                        writer.WriteLine(splitCopy[0]);
                                                                                                    }
                                                                                                }
                                                                                            }
                                                                                        }
                                                                                    }
                                                                                }


                                                                                if (!valid)
                                                                                {
                                                                                    totalLineIgnored++;
                                                                                    writerIgnoredLine.WriteLine(file + " ->" + line);
                                                                                }
                                                                            }
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }


                                                    }
                                                    totalLineRead++;

                                                }
                                            }

                                            totalFileRead++;
                                        }
                                        else
                                        {
                                            Console.WriteLine("File ignored: " + file);
                                            writerIgnored.WriteLine(file);
                                        }
                                    }
                                    catch(Exception error)
                                    {
                                        Debug.WriteLine("Error on line: " + file  + " | Exception: "+error.Message);
                                    }
                                }

                                if (totalPotentialWritten == 0)
                                    File.Delete(potentialFile);
                            }
                        }

                    }
                }
            }
            else
            {
                using (StreamWriter writer = new StreamWriter(pathFileSave, false, utf8Encoding) { AutoFlush = true })
                {
                    foreach (var fichier in files)
                    {

                        using (StreamReader reader = new StreamReader(fichier, utf8Encoding))
                        {
                            string line;
                            while ((line = reader.ReadLine()) != null)
                            {
                                if (!blockDuplicateLines.ContainsKey(line))
                                {
                                    if (blockDuplicateLines.Count >= 80_000_000 || !ClassRamStatus.RamAvailableStatus())
                                        blockDuplicateLines.Clear();
                                    
                                    blockDuplicateLines.Add(line, 0);
                                    writer.WriteLine(line);
                                    totalLineRead++;
                                }
                            }

                            totalFileRead++;
                        }
                    }
                }
            }

            blockDuplicateLines.Clear();
            finish = true;

            Console.WriteLine("Merge of " + files.Length + " files, ignored: " + totalLineRead);
            Console.WriteLine("Press a key to continue.");

            Console.ReadLine();
        }

        /// <summary>
        /// Split a file into several parts.
        /// </summary>
        private static void SplitFile()
        {
            Console.WriteLine("Select the file to split: ");

            string sourceFile = Console.ReadLine();

            Console.WriteLine("Choose the amount of parts: ");

            int part = int.Parse(Console.ReadLine());

            Console.WriteLine("Choose the path to save parts: ");

            string destFolder = Console.ReadLine();

            Console.WriteLine("Choose the basename of parts: ");

            string fileNamePart = Console.ReadLine();


            using (FileStream fs = File.Open(sourceFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            using (BufferedStream bs = new BufferedStream(fs, 8192))
            {
                Console.WriteLine("Count the amount of lines, please wait..");

                TotalLineFile = CountLinesMaybe(bs);
                Console.WriteLine("Amount of lines(s) to split: " + $"{TotalLineFile:#,##0.##}");
            }

            Console.WriteLine("Start to split the file..");

            long numberPart = TotalLineFile / part;
            long totalWritten = 0;
            int partId = 1;

            UTF8Encoding utf8Encoding = new UTF8Encoding(false);
            using (StreamReader reader = new StreamReader(sourceFile, utf8Encoding))
            {
                string line;

                StreamWriter writer = new StreamWriter(destFolder + "\\" + fileNamePart + partId, false, utf8Encoding);

                while ((line = reader.ReadLine()) != null)
                {
                    writer.WriteLine(line);

                    totalWritten++;
                    if (totalWritten >= numberPart)
                    {
                        if (partId + 1 < numberPart)
                        {
                            Debug.WriteLine("Fin de l'écriture du fichier ID: " + partId);
                            writer.Close();
                            partId++;
                            totalWritten = 0;
                            writer = new StreamWriter(destFolder + "\\" + fileNamePart + partId, false, utf8Encoding);
                        }
                    }
                }

                writer.Close();
            }

            Console.WriteLine("Cut of the file complete. Press a key to continue.");
            Console.ReadLine();
        }

        #region Functions dedicated to the generation of password reports.

        private static void ReadPasswordLine(string line)
        {
            try
            {
                line = Regex.Replace(line, @"[^\u0000-\u007F]", string.Empty);

                if (line.Length > 0)
                {
                    if (_iaPasswordDataObject.PasswordLengthRank.ContainsKey(line.Length))
                        _iaPasswordDataObject.PasswordLengthRank[line.Length]++;
                    else
                        _iaPasswordDataObject.PasswordLengthRank.Add(line.Length, 1);
                    

                    int pos = 0;

                    for (int i = 0; i < line.Length; i++)
                    {
                        if (i < line.Length)
                        {

                            if (_iaPasswordDataObject.PasswordCharacterRank.ContainsKey(line[i]))
                                _iaPasswordDataObject.PasswordCharacterRank[line[i]]++;
                            
                            else
                                _iaPasswordDataObject.PasswordCharacterRank.Add(line[i], 1);
                            
                            if (_iaPasswordDataObject.PasswordPosRank.ContainsKey(pos))
                            {
                                if (_iaPasswordDataObject.PasswordPosRank[pos].ContainsKey(line[i]))
                                    _iaPasswordDataObject.PasswordPosRank[pos][line[i]]++;
                                else
                                    _iaPasswordDataObject.PasswordPosRank[pos].Add(line[i], 1);
                                
                            }
                            else
                            {
                                _iaPasswordDataObject.PasswordPosRank.Add(pos, new SortedDictionary<char, decimal>());
                                if (_iaPasswordDataObject.PasswordPosRank[pos].ContainsKey(line[i]))
                                    _iaPasswordDataObject.PasswordPosRank[pos][line[i]]++;
                                else
                                    _iaPasswordDataObject.PasswordPosRank[pos].Add(line[i], 1);
                            }
                            pos++;
                        }
                    }

                    _currentFileLineRead++;

                }
            }
            catch
            {

            }
        }

        #endregion

        #region Functions dedicated to displaying the read status of passwords.

        /// <summary>
        /// Stops the task of displaying read passwords.
        /// </summary>
        private static void CloseTaskFileRead()
        {
            try
            {
                if (_cancellationTokenSourceReadFile != null)
                {
                    if (!_cancellationTokenSourceReadFile.IsCancellationRequested)
                    {
                        _cancellationTokenSourceReadFile.Cancel();
                    }
                }
            }
            catch
            {
                // Ignored.
            }
        }

        /// <summary>
        /// Lance une tâche d'affichage du nombre de mots de passes lus.
        /// </summary>
        /// <param name="nameFile"></param>
        private static void StartTaskFileRead(string nameFile)
        {
            CloseTaskFileRead();
            _currentFileLineRead = 0;
            _cancellationTokenSourceReadFile = new CancellationTokenSource();
            try
            {
                Task.Factory.StartNew(async () =>
                {
                    long totalPreviousCount = 0;
                    while (true)
                    {
                        _cancellationTokenSourceReadFile.Token.ThrowIfCancellationRequested();
                        if (_currentFileLineRead > 0)
                        {
                            if (totalPreviousCount > 0)
                            {
                                Debug.WriteLine("Speed: " + (_currentFileLineRead - totalPreviousCount) + " lines/s");
                            }


                            Debug.WriteLine("Total lines read: " + $"{_currentFileLineRead:#,##0.##}" + "/" + $"{TotalLineFile:#,##0.##}" + " from the file: " + nameFile);
                            totalPreviousCount = _currentFileLineRead;

                            await Task.Delay(1000);

                        }
                    }
                }, _cancellationTokenSourceReadFile.Token, TaskCreationOptions.LongRunning, TaskScheduler.Current).ConfigureAwait(false);
            }
            catch
            {
                // Catch the exception once the task is cancelled;
            }
        }

        /// <summary>
        /// Variables de paramètrage du comptage des lignes d'un fichier.
        /// </summary>
        private const char CR = '\r';
        private const char LF = '\n';
        private const char NULL = (char)0;

        /// <summary>
        /// Permet de lire rapidement le nombre de ligne.
        /// </summary>
        /// <param name="stream"></param>
        /// <returns></returns>
        public static long CountLinesMaybe(Stream stream)
        {

            var lineCount = 0L;

            var byteBuffer = new byte[1024 * 1024];
            const int BytesAtTheTime = 4;
            var detectedEOL = NULL;
            var currentChar = NULL;

            int bytesRead;
            while ((bytesRead = stream.Read(byteBuffer, 0, byteBuffer.Length)) > 0)
            {
                var i = 0;
                for (; i <= bytesRead - BytesAtTheTime; i += BytesAtTheTime)
                {
                    currentChar = (char)byteBuffer[i];

                    if (detectedEOL != NULL)
                    {
                        if (currentChar == detectedEOL) { lineCount++; }

                        currentChar = (char)byteBuffer[i + 1];
                        if (currentChar == detectedEOL) { lineCount++; }

                        currentChar = (char)byteBuffer[i + 2];
                        if (currentChar == detectedEOL) { lineCount++; }

                        currentChar = (char)byteBuffer[i + 3];
                        if (currentChar == detectedEOL) { lineCount++; }
                    }
                    else
                    {
                        if (currentChar == LF || currentChar == CR)
                        {
                            detectedEOL = currentChar;
                            lineCount++;
                        }
                        i -= BytesAtTheTime - 1;
                    }
                }

                for (; i < bytesRead; i++)
                {
                    currentChar = (char)byteBuffer[i];

                    if (detectedEOL != NULL)
                    {
                        if (currentChar == detectedEOL) { lineCount++; }
                    }
                    else
                    {
                        if (currentChar == LF || currentChar == CR)
                        {
                            detectedEOL = currentChar;
                            lineCount++;
                        }
                    }
                }
            }

            if (currentChar != LF && currentChar != CR && currentChar != NULL)
            {
                lineCount++;
            }
            return lineCount;
        }

        #endregion

        #region Fonctions dédiés à la génération des mots de passe.

        /// <summary>
        /// Vérifié les lignes des fichiers, compare et retourne vrai si le mot de passe existe déjà.
        /// </summary>
        /// <param name="pass"></param>
        /// <returns></returns>
        private static bool CheckDuplicateLine(string pass)
        {

            foreach (var streamObject in fileStreamDictionnary)
            {
                fileStreamDictionnary[streamObject.Key].StreamReader.BaseStream.Seek(0, SeekOrigin.Begin);
                fileStreamDictionnary[streamObject.Key].StreamReader.BaseStream.Position = 0;


                try
                {
                    Dictionary<string, int> dictionaryComparaison = fileStreamDictionnary[streamObject.Key].StreamReader.ReadToEnd().Split(new[] { "\n" }, StringSplitOptions.None).ToDictionary(key => key, value => 0);
                    if (dictionaryComparaison.Count > 0)
                    {
                        if (dictionaryComparaison.ContainsKey(pass))
                        {
                            dictionaryComparaison.Clear();
                            return true;
                        }
                        dictionaryComparaison.Clear();
                    }
                }
                catch
                {
                    // Ignored.
                }
            }

            return false;
        }

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

        #endregion

        #region Other functions.

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
        private static bool SplitMergedPassFromEmail(string line, string characterSeperator, out string newLine, out bool ignoreHex, out bool converted)
        {
            ignoreHex = false;
            converted = false;
            if (line.Contains(characterSeperator))
            {

                if (line.Count(x => x == characterSeperator[0]) == 1)
                {
                    string[] lineSplit = line.Split(new[] { characterSeperator }, StringSplitOptions.None);
                    if (_regexEmail.IsMatch(lineSplit[0]) || (lineSplit[0].Contains("@") && lineSplit[0].Contains(".")))
                    {
                        newLine = lineSplit[1];
                        if (_regexHex.IsMatch(newLine) && newLine.Length >= 32)
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

                        if(newLine.Contains("$HEX[") || newLine.Contains("$hex["))
                        {
                            newLine = newLine.Replace("$HEX[", "");
                            newLine = newLine.Replace("$hex[", "");
                            newLine = newLine.Replace("]", "");
                            var hexBytes = GetByteArrayFromHexString(newLine);
                            if(hexBytes != null)
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

                        if(newLine.Contains(" | "))
                        {
                            int indexOf = newLine.IndexOf(" | ");
                            var newLineTest = newLine.Substring(0, indexOf);

                            newLine = newLineTest;
                            converted = true;
                        }

                        if (_regexEmail.IsMatch(newLine))
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
                                            if (!_regexEmail.IsMatch(splitNewLine[1]) && !_regexHex.IsMatch(splitNewLine[1]))
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

                        if (timestamp +5 < DateTimeOffset.Now.ToUnixTimeSeconds())
                        {
                            Debug.WriteLine("Error stuck on splitting line: "+line);
                            break;
                        }
                    }


                    if (_regexEmail.IsMatch(email))
                    {
                        if (_regexHex.IsMatch(pass) && pass.Length >= 32)
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

                            if (_regexEmail.IsMatch(newLine))
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
                                                if (!_regexEmail.IsMatch(splitNewLine[1]) && !_regexHex.IsMatch(splitNewLine[1]))
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


                    if (_regexEmail.IsMatch(email) || (email.Contains("@") && email.Contains(".")))
                    {
                        if ((_regexHex.IsMatch(pass) && pass.Length >= 32) || pass.Length >= 32)
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

                            if (_regexEmail.IsMatch(newLine))
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
                                                if (!_regexEmail.IsMatch(splitNewLine[1]) && !_regexHex.IsMatch(splitNewLine[1]))
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

        private static Regex _regexHex = new Regex(@"\A\b[0-9a-fA-F]+\b\Z");

        private static string RemoveControlCharacter(string line)
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

                Debug.WriteLine("Error on hex string: " + hex);
                return null;
            }
        }


        private static Regex _regexEmail = new Regex(@"^[\w.-]+@(?=[a-z\d][^.]*\.)[a-z\d.-]*[^.]$");

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

        private static bool IsEmail(string line, out bool fixedLine, out string newLine)
        {

            fixedLine = false;
            newLine = string.Empty;
            Match match = _regexEmail.Match(line);
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

                                    Match matchNewLine = _regexEmail.Match(splitLineTwo[1]);

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

                                Match matchNewLine = _regexEmail.Match(splitLine[1]);

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
                                Match matchNewLine = _regexEmail.Match(splitLine[1]);

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
                                    Match matchNewLine = _regexEmail.Match(splitLine[1]);

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
                                Match matchNewLine = _regexEmail.Match(splitLine[1]);

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

        private static bool CheckWord(string line)
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

        #endregion
    }

}
