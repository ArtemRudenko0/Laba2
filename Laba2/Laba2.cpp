#define _WIN32_DCOM

#include <iostream>
#include <comdef.h>
#include <Wbemidl.h>
#include <string>

#pragma comment(lib, "wbemuuid.lib")

using namespace std;

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
    // Отримати дані з запиту в кроці 6 -------------------
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
            wcout << L"Keyboard Name: " <<  bstr_t(vtName.bstrVal) << endl;
            wcout << L"Keyboard NumberOfFunctionKeys: " << vtNumberOfFunctionKeys.intVal << endl;
        }
        else cout << "Failed to retrieve Keyboard info" << endl;
  
        VariantClear(&vtDescription);
        VariantClear(&vtName);
        VariantClear(&vtNumberOfFunctionKeys);

        pclsObj->Release();
    }
   

    psvc->Release();
    ploc->Release();
    pEnumerator->Release();
    pclsObj->Release();
    CoUninitialize();
    return 0; // Програма завершена.

}

