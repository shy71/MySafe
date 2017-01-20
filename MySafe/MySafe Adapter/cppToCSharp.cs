using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Runtime.InteropServices;
using System.Reflection;

namespace MySafe_Adapter
{
    public class cppToCsharpAdapter
    {
        const string dllPath = "Bridge DLL.dll";
        [DllImport(dllPath, CallingConvention = CallingConvention.Cdecl)]
        public static extern void load_valut(IntPtr THIS,string path,string master_password);
    }
}
