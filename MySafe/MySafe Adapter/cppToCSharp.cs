using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Reflection;
using System.IO;

namespace MySafe_Adapter
{
    public class cppToCsharpAdapter
    {
        static public string GG()
        {
           return Directory.GetCurrentDirectory();
        }
        const string dllPath = "Bridge DLL.dll";
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr getFileVaultObj();
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern void create_valut(IntPtr obj, string path,string master_password);
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern void close_valut(IntPtr obj);
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern void load_valut(IntPtr obj, string path, string master_password);
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern void encrypt_file(IntPtr obj, string path,string new_path, string file_password);
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern void decrypt_file(IntPtr obj, string path,string newpath, string file_password);
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern IntPtr GetLastFileVaultErrorMessage(IntPtr obj);
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern void deleteFileVaultobj(ref IntPtr obj);
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern int is_vault_open(IntPtr obj);
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern double get_precntege_of_process(IntPtr obj);
        
    }
}
