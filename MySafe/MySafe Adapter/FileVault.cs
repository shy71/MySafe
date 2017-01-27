using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace MySafe_Adapter
{
    public class FileVault
    {
        #region Variables
        IntPtr myFileVaultPointer;

        private string fileName;
        /// <summary>
        /// The file name of the current open vault
        /// </summary>
        public string FileName
        {
            get { return fileName; }
        }

        private string filePath;
        /// <summary>
        /// The File Path of the current open vault
        /// </summary>
        public string FilePath
        {
            get { return filePath; }
        }
        #endregion

        #region Constructor & Destructor
        public FileVault()
        {
            myFileVaultPointer = cppToCsharpAdapter.getFileVaultObj();
        }
        ~FileVault()
        {
            if (myFileVaultPointer != null)
                cppToCsharpAdapter.deleteFileVaultobj(ref myFileVaultPointer);
        }
        #endregion

        #region Vault Functions
        /// <summary>
        /// Create a new vault file
        /// </summary>
        /// <param name="path">Path for the vault file</param>
        /// <param name="masterPassword">Master password for the vault</param>
        public void CreateVault(string path, string masterPassword)
        {
            try
            {
                if (path.Length > 250)
                    throw new Exception("Path length is to long! Max 250 characters");
                if (isVaultOpen())
                    throw new Exception("There is an already open vault, close it before opening a new one");
                cppToCsharpAdapter.create_vault(this.myFileVaultPointer, path, masterPassword);
                if (isVaultOpen())
                {
                    fileName = Path.GetFileName(path);
                    filePath = path;
                }
            }
            catch (SEHException)
            {
                IntPtr cString = cppToCsharpAdapter.GetLastFileVaultErrorMessage(this.myFileVaultPointer);
                string message = Marshal.PtrToStringAnsi(cString);
                throw new Exception(message);
            }
            catch
            {
                throw;
            }
        }
        /// <summary>
        /// Loads a vault file
        /// </summary>
        /// <param name="path">Path for the vault file</param>
        /// <param name="masterPassword">Master password for the vault</param>
        public void LoadVault(string path, string masterPassword)
        {
            try
            {
                if (path.Length > 250)
                    throw new Exception("Path length is to long! Max 250 characters");
                if (isVaultOpen())
                    throw new Exception("There is an already open vault, close it before opening a new one");
                cppToCsharpAdapter.load_vault(this.myFileVaultPointer, path, masterPassword);
                if (isVaultOpen())
                {
                    fileName = Path.GetFileName(path);
                    filePath = path;
                }
            }
            catch (SEHException)
            {
                IntPtr cString = cppToCsharpAdapter.GetLastFileVaultErrorMessage(this.myFileVaultPointer);
                string message = Marshal.PtrToStringAnsi(cString);
                throw new Exception(message);
            }
            catch
            {
                throw;
            }
        }
        /// <summary>
        /// Checks wheter a vault is open
        /// </summary>
        /// <returns>True if there is an open vault righ now; Flase if there isn't</returns>
        public bool isVaultOpen()
        {
            try
            {
                return (cppToCsharpAdapter.is_vault_open(this.myFileVaultPointer) == 1);
            }
            catch (SEHException)
            {
                IntPtr cString = cppToCsharpAdapter.GetLastFileVaultErrorMessage(this.myFileVaultPointer);
                string message = Marshal.PtrToStringAnsi(cString);
                throw new Exception(message);
            }
            catch
            {
                throw;
            }
        }
        /// <summary>
        /// Close the current vault
        /// </summary>
        public void CloseVault()
        {
            try
            {
                cppToCsharpAdapter.close_vault(this.myFileVaultPointer);
                if (!isVaultOpen())
                {
                    fileName = "";
                    filePath = "";
                }
                else
                    throw new Exception("Error: Vault wasn't closed!");
            }
            catch (SEHException)
            {
                IntPtr cString = cppToCsharpAdapter.GetLastFileVaultErrorMessage(this.myFileVaultPointer);
                string message = Marshal.PtrToStringAnsi(cString);
                throw new Exception(message);
            }
            catch
            {
                throw;
            }
        }
        #endregion

        #region Files Functions
        /// <summary>
        /// Encrypt File
        /// </summary>
        /// <param name="path">Path for the file to be encrypted</param>
        /// <param name="newPath">Path for the new encrypted file</param>
        /// <param name="filePassword">Password for the file encryption</param>
        /// <param name="deleteOriginal">Wherer the orignal file should be deleted</param>
        public void EncryptFile(string path, string newPath, string filePassword, bool deleteOriginal)
        {
            try
            {
                if (path.Length > 250 || newPath.Length > 250)
                    throw new Exception("Path length is to long! Max 250 characters");
                cppToCsharpAdapter.encrypt_file(this.myFileVaultPointer, path, newPath, filePassword, deleteOriginal);
            }
            catch (SEHException)
            {
                IntPtr cString = cppToCsharpAdapter.GetLastFileVaultErrorMessage(this.myFileVaultPointer);
                string message = Marshal.PtrToStringAnsi(cString);
                throw new Exception(message);
            }
            catch
            {
                throw;
            }
        }
        /// <summary>
        /// Decrypt File
        /// </summary>
        /// <param name="encryptedFilePath">Path for the file to be decrypted</param>
        /// <param name="newPlainTextPath">Path for the new decrypted file</param>
        /// <param name="filePassword">Password for the file decryption</param>
        /// <param name="deleteEncrypted">Wherer the encrypted file should be deleted</param>
        public void DecryptFile(string encryptedFilePath, string newPlainTextPath, string filePassword, bool deleteEncrypted)
        {
            try
            {
                if (encryptedFilePath.Length > 250 || newPlainTextPath.Length > 250)
                    throw new Exception("Path length is to long! Max 250 characters");
                cppToCsharpAdapter.decrypt_file(this.myFileVaultPointer, encryptedFilePath, newPlainTextPath, filePassword, deleteEncrypted);
            }
            catch (SEHException)
            {
                IntPtr cString = cppToCsharpAdapter.GetLastFileVaultErrorMessage(this.myFileVaultPointer);
                string message = Marshal.PtrToStringAnsi(cString);
                throw new Exception(message);
            }
            catch
            {
                throw;
            }
        }
        /// <summary>
        /// Get the Precntege of the current running process
        /// </summary>
        /// <returns>Precntege of the current running process</returns>
        public double GetPrecntegeOfProcess()
        {
            try
            {
                return cppToCsharpAdapter.get_precntege_of_process(this.myFileVaultPointer);
            }
            catch (SEHException)
            {
                IntPtr cString = cppToCsharpAdapter.GetLastFileVaultErrorMessage(this.myFileVaultPointer);
                string message = Marshal.PtrToStringAnsi(cString);
                throw new Exception(message);
            }
            catch
            {
                throw;
            }
        }
        #endregion
    }
}
