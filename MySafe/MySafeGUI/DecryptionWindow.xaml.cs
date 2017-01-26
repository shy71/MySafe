﻿using System;
using System.IO;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Shapes;
using MySafe_Adapter;
using Microsoft.Win32;
using System.Threading;

namespace MySafeGUI
{
    /// <summary>
    /// Interaction logic for DecryptionWindow.xaml
    /// </summary>
    public partial class DecryptionWindow : Window
    {
        FileVault vault;
        string srcPath = "";
        string destPath = "";
        public DecryptionWindow(FileVault v)
        {
            InitializeComponent();
            vault = v;
            OpenfilePath_Click(null, null);

        }
        public DecryptionWindow()
        {
            InitializeComponent();
        }

        private void OpenfilePath_Click(object sender, RoutedEventArgs e)
        {
            var openFile = new OpenFileDialog();
            openFile.Filter = "Encrypted Files(*.ens) | *.ens|All Files(*.*) | *.*";
            openFile.ShowDialog();
            srcPath = openFile.FileName;
            if (srcPath.Length > 0)
            {
                openFilePath.ToolTip = srcPath;
                openFilePath.Text = System.IO.Path.GetFileName(srcPath);
                if (destPath.Length == 0)
                {
                    destPath = System.IO.Path.GetDirectoryName(srcPath) + "\\" + System.IO.Path.GetFileNameWithoutExtension(srcPath);
                    saveFilePath.ToolTip = destPath;
                    saveFilePath.Text = System.IO.Path.GetFileName(destPath);
                }
            }
            else
            {
                srcPath = "";
                openFilePath.ToolTip = "Press to Choose encrypted file";
                openFilePath.Text = "Encrypted File: No file was chosen";
                if (destPath.Length == 0)
                {
                    saveFilePath.ToolTip = "Press to Choose destnation path";
                    saveFilePath.Text = "Destnation path: No file was chosen";
                }
            }
        }
        private void Decrypt_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                if (destPath == "")
                    throw new Exception("The Destnation path is empty");
                if (srcPath == "")
                    throw new Exception("No File was chosen to be decrypted");
                if (password.GetText() == null)
                    throw new Exception("The password field is empty");
                openFilePath.IsEnabled = false;
                saveFilePath.IsEnabled = false;
                decryptBtn.IsEnabled = false;
                progressBar.Value = 0;
                progressBar.ToolTip = 0;
                label.Visibility = Visibility.Visible;
                new Task((password) =>
                {
                    try
                    {
                        vault.DecryptFile(srcPath, destPath, password.ToString());
                        Dispatcher.Invoke(() =>
                        {
                            progressBar.Value = 100;
                            MessageBox.Show("The File has been decrypted successfully.\n" + destPath, "File Decrypted", MessageBoxButton.OK, MessageBoxImage.Information, MessageBoxResult.OK);
                            this.Close();
                        });
                    }
                    catch(Exception ex)
                    {
                        Dispatcher.Invoke(() =>
                        {
                            MessageBox.Show(ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error, MessageBoxResult.OK);
                        });
                    }
                }, password.GetText()).Start();
                new Task(() =>
                {
                    double progress = 0;
                    while (progress < 99.8)
                    {
                        Thread.Sleep(20);
                        progress = vault.GetPrecntegeOfProcess();
                        Dispatcher.Invoke(() =>
                        {
                            progressBar.Value = progress;
                            progressBar.ToolTip = Math.Round(progress, 2);
                        });
                    }
                }).Start();
                //vault.EncryptFile(srcPath, destPath, password.GetText());
                //this.Close();
            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message, "Error", MessageBoxButton.OK, MessageBoxImage.Error, MessageBoxResult.OK);
            }
        }

        private void SavefilePath_Click(object sender, RoutedEventArgs e)
        {
            var saveFile = new SaveFileDialog();
            saveFile.Filter= "All Files(*.*) | *.*";
            saveFile.ShowDialog();
            destPath = saveFile.FileName;
            if (destPath.Length > 0)
            {
                saveFilePath.ToolTip = destPath;
                saveFilePath.Text = System.IO.Path.GetFileName(destPath);
            }
            else
            {
                destPath = "";
                saveFilePath.ToolTip = "Press to Choose path";
                saveFilePath.Text = "Decrypted Path: No path was chosen";
            }
        }
    }
}
