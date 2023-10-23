#define _WIN32_DCOM

#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>
#include <string>
#include <oleauto.h>
#include <Windows.h>
#pragma comment(lib, "wbemuuid.lib")

using namespace std;
SYSTEMTIME WMIDateStringToDate(BSTR WMIdateString);
int main()
{

    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);

    HRESULT hres;
    IWbemLocator* ploc = NULL;
    IWbemServices* psvc = NULL;

    IEnumWbemClassObject* pEnumerator = NULL;

    IWbemClassObject* pclsObj = NULL;

    ULONG uReturn = 0;

    // Крок 1:
    // ініціалізувати COM.
    hres = CoInitializeEx(0, COINIT_MULTITHREADED);
    if (FAILED(hres))
    {
        cout << "Не Вдалося Ініціалізувати бібліотеку COM.Помилка коду = 0x"
            << hex << hres << endl;
        return 1; // Програма провалилася.
    }
    // Крок 2:
    // Установити загальні COM рівні безпеки
    // Примітка: Вам необхідно вказати - за замовчуванням облікові дані для
    //аутентифікації користувача за допомогою
    // SOLE AUTHENTICATION LISTструктури в pauthlist —
    // параметр Coinitializesecurity
    hres = CoInitializeSecurity(
        NULL,
        -1,
        NULL,
        NULL,
        RPC_C_AUTHN_LEVEL_DEFAULT,
        RPC_C_IMP_LEVEL_IMPERSONATE,
        NULL,
        EOAC_NONE,
        NULL
    );
    if (FAILED(hres))
    {
        cout << "Не Вдалося безпечно ініціалізувати.Код помилки = 0х"
            << hex << hres << endl;
        CoUninitialize();
        return 1; // Програма закінчена.
    }
    else cout << "Initialized code" << endl;
    //Крок 3:
    // Одержання первинного локатора для WMI
    hres = CoCreateInstance(
        CLSID_WbemLocator,
        0,
        CLSCTX_INPROC_SERVER,
        IID_IWbemLocator,
        (LPVOID*)&ploc
    );
    if (FAILED(hres))
    {
        cout << "Не Вдалося створити Iwbemlocator об’єкт."
            << "Помилка коду = 0x"
            << hex << hres << endl;
        CoUninitialize();
        return 1; // Завершення програми.
    }
    else cout << "Created IwbemLocator object" << endl;
    // Крок 4:
    // Підключення до WMI через Iwbemlocator::Connectserver метод
    hres = ploc->ConnectServer(
        _bstr_t(L"root\\CIMV2"), //Шлях до об’єкта WMI
        NULL, // Ім’я користувача. NULL = поточний користувач.
        NULL, //Пароль користувача. NULL = поточний пароль.
        0,
        NULL,
        0,
        0,
        &psvc //покажчик Iwbemservices proxy 
    );
    if (FAILED(hres))
    {
        cout << " Не Вдалося підключитися. Помилка коду = 0x"
            << hex << hres << endl; ploc->Release();
        CoUninitialize();
        return 1; // Завершення програми.
    }
    else cout << "Conneted ROOT\\CIMV2 WMI" << endl;

    // Крок 5:
    // Установити рівень безпеки на проксі
    hres = CoSetProxyBlanket(psvc, // Покажчик на проксі
        RPC_C_AUTHN_WINNT, // RPC_C_AUTHN_xxx
        RPC_C_AUTHZ_NONE, // RPC_C_AUTHZ_xxx
        NULL, // Им’я участника на сервері
        RPC_C_AUTHN_LEVEL_CALL, // RPC_C_AUTHN_LEVEL_xxx
        RPC_C_IMP_LEVEL_IMPERSONATE, // RPC_C_IMP_LEVEL_xxx
        NULL, // ідентифікація клієнта
        EOAC_NONE // проксі можливості
    );
    if (FAILED(hres))
    {
        cout << "Не вдалося встановити безпеку на сервері.Помилка коду = 0x"
            << hex << hres << endl;
        psvc->Release();
        ploc->Release();
        CoUninitialize();
        return 1; // Завершення програми.
    }
    else cout << "Security ON" << endl;

    // Крок 6:
    // Використовувати Iwbemservices покажчик щоб зробити запити WMI --
    // наприклад на одержання імені операційної системи
   


    
    hres = psvc->ExecQuery(
        bstr_t("WQL"),
        bstr_t("SELECT * FROM Win32_Keyboard"),
        WBEM_FLAG_FORWARD_ONLY |
        WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator);
    if (FAILED(hres))
    {
        cout << "Інформація про клавіатуру не отримано."
            << " помилка коду = 0x"
            << hex << hres << endl;
        psvc->Release();
        ploc->Release();
        CoUninitialize();
        return 1; // Програма завершена.
    }
    else cout << "\nGot keyboard info" << endl;

    // Крок 7: -------------------------------------------------

    //Завдання 1
    while (pEnumerator)
    {


        HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1,
            &pclsObj, &uReturn);

        if (0 == uReturn)
        {
            break;
        }

        VARIANT vtDescription;
        VARIANT vtName;
        VARIANT vtNumberOfFunctionKeys;

        VariantInit(&vtDescription);
        VariantInit(&vtName);
        VariantInit(&vtNumberOfFunctionKeys);

        // Get the value of the Name property
        hr = pclsObj->Get(SysAllocString(L"Description"), 0, &vtDescription, 0, 0);
        hr = pclsObj->Get(SysAllocString(L"Name"), 0, &vtName, 0, 0);
        hr = pclsObj->Get(SysAllocString(L"NumberOfFunctionKeys"), 0, &vtNumberOfFunctionKeys, 0, 0);

        if (SUCCEEDED(hr) && vtDescription.vt == VT_BSTR
            && vtName.vt == VT_BSTR
            && vtNumberOfFunctionKeys.vt == VT_I4)
        {
            wcout << L"Keyboard Description: " << bstr_t(vtDescription.bstrVal) << endl;
            wcout << L"Keyboard Name: " << bstr_t(vtName.bstrVal) << endl;
            wcout << L"Keyboard NumberOfFunctionKeys: " << vtNumberOfFunctionKeys.intVal << endl;
        }
        else cout << "Failed to retrieve Keyboard info" << endl;

        VariantClear(&vtDescription);
        VariantClear(&vtName);
        VariantClear(&vtNumberOfFunctionKeys);

        pclsObj->Release();
    }
    system("pause");
    //IWbemClassObject* pClass = NULL;
    //Завдання 2
    
    hres = psvc->GetObject(_bstr_t("Win32_Keyboard"), 0, NULL, &pclsObj, NULL);

    if (FAILED(hres))
    {
        cout << "GetObject failed" << " Error code = 0x" << hex << hres << endl;
        cout << _com_error(hres).ErrorMessage() << endl;
        psvc->Release();
        ploc->Release();
        CoUninitialize();
        cout << "press enter to exit" << endl;
        cin.get();
        return 1;               // Program has failed.
    }

    SAFEARRAY* psaNames = NULL;
    hres = pclsObj->GetNames(
        NULL,
        WBEM_FLAG_ALWAYS | WBEM_FLAG_NONSYSTEM_ONLY,
        NULL,
        &psaNames);
    if (FAILED(hres))
    {
        cout << "GetNames failed" << " Error code = 0x" << hex << hres << endl;
        cout << _com_error(hres).ErrorMessage() << endl;
        psvc->Release();
        ploc->Release();
        CoUninitialize();
        cout << "press enter to exit" << endl;
        cin.get();
        return 1;               // Program has failed.
    }
    long lLower, lUpper;
    BSTR PropName = NULL;
    SafeArrayGetLBound(psaNames, 1, &lLower);
    SafeArrayGetUBound(psaNames, 1, &lUpper);
    cout << "\nWin32_Keyboard Properties: " << endl;
    for (long i = lLower; i <= lUpper; i++)
    {
        // Get this property.
        hres = SafeArrayGetElement(
            psaNames,
            &i,
            &PropName);

        wcout << PropName << endl;
        SysFreeString(PropName);
    }

    SafeArrayDestroy(psaNames);
   
    system("pause");
   
    //Завдання 3.а - 3.e
    
    STARTUPINFO si = { sizeof(STARTUPINFO) };
    PROCESS_INFORMATION pi;

    hres = psvc->ExecQuery(
        _bstr_t("WQL"),
        _bstr_t("SELECT * FROM Win32_Process WHERE Name = 'MSACCESS.EXE'"),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );
    int processID = 0;
    if (SUCCEEDED(hres)) {
        IWbemClassObject* pclsObj = NULL;
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOWMAXIMIZED;
        LPCTSTR appPath = L"C:\\Program Files\\Microsoft Office\\root\\Office16\\MSACCESS.EXE";  // Ваш шлях до MS Access
        // Параметри для виклику MS Access
        WCHAR cmdLine[] = L"C:\\Users\\АРТЕМ\\Desktop\\Database1.accdb"; // Шлях до вашої бази даних
        LPCTSTR cmdDir = NULL; // Робочий каталог (можна вказати NULL для поточного каталогу)
        CreateProcess(appPath, cmdLine, NULL, NULL, FALSE, HIGH_PRIORITY_CLASS, NULL, cmdDir, &si, &pi);
        Sleep(2000);
        cout << endl;
        while (pEnumerator) {
            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

            if (uReturn == 0) {
                break;
            }

            VARIANT vtProp;
            hres = pclsObj->Get(L"ExecutablePath", 0, &vtProp, 0, 0);
            wprintf(L"ExecutablePath: %s\n", vtProp.bstrVal);

            hres = pclsObj->Get(L"CreationDate", 0, &vtProp, 0, 0);
            SYSTEMTIME st = WMIDateStringToDate(vtProp.bstrVal);

            wprintf(L"CreationDate: %04d-%02d-%02d %02d:%02d:%02d\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
            // Можете конвертувати цю дату за допомогою WMIDateStringToDate()


            hres = pclsObj->Get(L"Priority", 0, &vtProp, 0, 0);
            wprintf(L"Priority: %u\n", vtProp.uintVal);

            hres = pclsObj->Get(L"ProcessID", 0, &vtProp, 0, 0);
            processID = vtProp.uintVal;
            wprintf(L"ProcessID: %u\n", vtProp.uintVal);

            hres = pclsObj->Get(L"ThreadCount", 0, &vtProp, 0, 0);
            wprintf(L"ThreadCount: %u\n", vtProp.uintVal);

            // Отримуємо інформацію про процес MS Access
        }
    }
    //Завдання 3.f
    hres = psvc->ExecQuery(
        _bstr_t("WQL"),
        _bstr_t("SELECT * FROM Win32_Thread WHERE ProcessHandle = " + _bstr_t(std::to_wstring(processID).c_str())),
        WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
        NULL,
        &pEnumerator
    );
    if (SUCCEEDED(hres)) {
        IWbemClassObject* pclsObj = NULL;
        ULONG uReturn = 0;
        int count = 0;
        while (pEnumerator)
        {
            HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);

            if (0 == uReturn)
            {
                break;
            }

            VARIANT vtProp;
            cout << "\n" << count + 1 << " Thread: " << endl;
            // Извлеките свойства потока, включая требуемую информацию
            hr = pclsObj->Get(L"ProcessHandle", 0, &vtProp, 0, 0);
            wprintf(L"ProcssHandle: %s\n", vtProp.bstrVal);
            VariantClear(&vtProp);

            hr = pclsObj->Get(L"Priority", 0, &vtProp, 0, 0);
            wprintf(L"Priority: %d\n", V_I4(&vtProp));
            VariantClear(&vtProp);

            hr = pclsObj->Get(L"PriorityBase", 0, &vtProp, 0, 0);
            wprintf(L"PriorityBase: % d\n", V_I4(&vtProp));
            VariantClear(&vtProp);

            hr = pclsObj->Get(L"UserModeTime", 0, &vtProp, 0, 0);
            wprintf(L"UserModeTime: %I64d\n", V_I8(&vtProp));
            VariantClear(&vtProp);

            hr = pclsObj->Get(L"ThreadState", 0, &vtProp, 0, 0);
            wprintf(L"ThreadState: %d\n", V_I4(&vtProp));
            VariantClear(&vtProp);

            pclsObj->Release();
            count++;
        }
        cout << "\n" << count << " Threads" << endl;
    }
    system("pause");
    // Завдання 4
   
        hres = psvc->ExecQuery(
            _bstr_t(L"WQL"),
            _bstr_t(L"SELECT Name, ReadTransferCount FROM Win32_Process "),
            WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
            NULL,
            &pEnumerator
        );
        if (SUCCEEDED(hres)) {
            ULONG uReturn = 0;
            IWbemClassObject* pclsObj = NULL;
            unsigned long long max = 0;
            _bstr_t MaxName;
            _bstr_t MaxReadTransferCount;
            while (pEnumerator) {
                HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
                if (0 == uReturn)
                {
                    break;
                }
                VARIANT vtName, vtReadTransferCount;
                hr = pclsObj->Get(SysAllocString(L"Name"), 0, &vtName, 0, 0);
                hr = pclsObj->Get(SysAllocString(L"ReadTransferCount"), 0, &vtReadTransferCount, 0, 0);
                if (SUCCEEDED(hr)) {
                    unsigned long long readTransferCount = _wcstoui64(vtReadTransferCount.bstrVal, NULL, 10);
                    if (readTransferCount > max) {
                        max = readTransferCount;
                        //MaxReadTransferCount = vtReadTransferCount.bstrVal;
                        MaxName = vtName.bstrVal;
                        //std::wcout << L"\nProcess Name: " << MaxName << std::endl;
                        //std::wcout << L"\nReadTransferCount: " << SysAllocString(std::to_wstring(max).c_str()) << std::endl;

                    }
                }
               


                VariantClear(&vtName);
                VariantClear(&vtReadTransferCount);
                pclsObj->Release();
            }
            std::wcout << L"\nProcess Name: " << MaxName << std::endl;
            std::wcout << L"\nReadTransferCount: " << SysAllocString(std::to_wstring(max).c_str()) << std::endl;
           // std::wcout << L"\nReadTransferCount: " << MaxReadTransferCount << std::endl;

        }
    
        system("pause");
        
       
   //Завдання 5.а
     hres = psvc->ExecQuery(
        _bstr_t(L"WQL"),
        _bstr_t(L"SELECT * FROM Win32_Process WHERE Name = 'notepad.exe' AND Priority = 4"),
         WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
         NULL,
         &pEnumerator
        );
     if (SUCCEEDED(hres)) {
         ULONG uReturn = 0;
         IWbemClassObject* pclsObj = NULL;
         int count = 0;
         
         while (pEnumerator) {
             HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
             if (0 == uReturn) {
                 break;
             }

             // Получение PID процесса
             VARIANT vtProcessID;
             hr = pclsObj->Get(L"ProcessID", 0, &vtProcessID, 0, 0);
             if (SUCCEEDED(hr)) {
                 int processID = vtProcessID.intVal;

                 // Завершение процесса
                 HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processID);
                 if (hProcess != NULL) {
                     TerminateProcess(hProcess, 0);
                     CloseHandle(hProcess);
                     cout << "Closed process with id: " << processID << endl;
                     count++;
                 }
             }

             VariantClear(&vtProcessID);
             pclsObj->Release();
         }
         cout << "Closed " << count << "x 'notepad.exe'" << endl;
      
     }
     //Завдання 5.b
     system("pause");
     int totalCmdID = 0;
     hres = psvc->ExecQuery(
         _bstr_t("WQL"),
         _bstr_t("SELECT * FROM Win32_Process WHERE Name = 'TOTALCMD64.EXE'"),
         WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
         NULL,
         &pEnumerator
     );
     if (SUCCEEDED(hres)) {
         
         ULONG uReturn = 0;
         HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
         VARIANT vtProcessID;
         hr = pclsObj->Get(L"ProcessID", 0, &vtProcessID, 0, 0);
         if (SUCCEEDED(hr)) {
             totalCmdID = vtProcessID.uintVal;
         }
         VariantClear(&vtProcessID);
         pclsObj->Release();
     }
     cout << "ParentProcessId = " << totalCmdID << endl;
     hres = psvc->ExecQuery(
         _bstr_t(L"WQL"),
         _bstr_t(L"SELECT * FROM Win32_Process WHERE ParentProcessId = " + _bstr_t(std::to_wstring(totalCmdID).c_str())),
         WBEM_FLAG_FORWARD_ONLY | WBEM_FLAG_RETURN_IMMEDIATELY,
         NULL,
         &pEnumerator
     );
     if (SUCCEEDED(hres)) {
         ULONG uReturn = 0;
         IWbemClassObject* pclsObj = NULL;
         int count = 0;

         while (pEnumerator) {
             HRESULT hr = pEnumerator->Next(WBEM_INFINITE, 1, &pclsObj, &uReturn);
             if (0 == uReturn) {
                 break;
             }

             // Получение PID процесса
             VARIANT vtProcessID;
             hr = pclsObj->Get(L"ProcessID", 0, &vtProcessID, 0, 0);
             if (SUCCEEDED(hr)) {
                 int processID = vtProcessID.intVal;

                 // Завершение процесса
                 HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, processID);
                 if (hProcess != NULL) {
                     TerminateProcess(hProcess, 0);
                     CloseHandle(hProcess);
                     cout << "Closed process with id: " << processID << endl;
                     count++;
                 }
             }

             VariantClear(&vtProcessID);
             pclsObj->Release();
         }
         cout << "Closed " << count << "x processes launched by Total Commander" << endl;

     }
    psvc->Release();
    ploc->Release();
    pEnumerator->Release();
    pclsObj->Release();
    CoUninitialize();
    return 0; // Програма завершена.


}

SYSTEMTIME WMIDateStringToDate(BSTR WMIdateString) {
    SYSTEMTIME st = { 0 };
    int year, month, day, hour, minute, second, microseconds, offset;
    int result = swscanf_s(WMIdateString, L"%4d%2d%2d%2d%2d%2d.%6d%5d",
        &year, &month, &day, &hour, &minute, &second, &microseconds, &offset);

    if (result != 8) {
        wprintf(L"Failed to parse WMI date string.\n");
        return st;
    }
    st.wYear = static_cast<WORD>(year);
    st.wMonth = static_cast<WORD>(month);
    st.wDay = static_cast<WORD>(day);
    st.wHour = static_cast<WORD>(hour);
    st.wMinute = static_cast<WORD>(minute);
    st.wSecond = static_cast<WORD>(second);
    return st;
}
