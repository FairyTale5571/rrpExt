#define freeExtension comment

// Test script "test_script.sqf" to demonstrate 
// the functionality of "callExtension" executable
// Name of the script could be any
// Instructions processed 1 per line
// Lines starting with # are ignored
// Wait for 3.7 seconds...

sleep 3.7;

// An extension version is now shown automatically 
// when the extenstion is called for the first time
// Invoke String variant of callExtension

sleep 3.2;

"test_extension" callExtension "Just passing a string to the dll";

sleep 1;

// Invoke Array variant of callExtension calling "fnc1" routine
"test_extension" callExtension ["fnc1",[1,2,3,[true,false],"string","string with ""quotes"""]];

sleep 7.2;

// Invoke Array variant of callExtension calling "fnc2" routine
// Any non-number, non-string, non-boolean will be converted to nil
"test_extension" callExtension ["fnc2",[1,2,3,[true],not_string_number_bool]]];

sleep 8.1;

// Invoke Array variant of callExtension calling non-existent routine
"test_extension" callExtension ["non-existent",[]];

sleep 7.9;

// Launch "test_script2.sqf"
execVM "test_script2.sqf";

// Resume main script and unload the extension
// (this command is not available in Arma 3)
freeExtension "test_extension";

// Testing unicode support
// (unloaded extension will be reloaded)
"test_extension" callExtension "Bonjour!, Salut!, Ça marche?";
"test_extension" callExtension "Grüß ihn von mir";
"test_extension" callExtension "Здрасте, я ваша Настя";

sleep 7;

// Some unrecognised command
hint "hello";

sleep 3;

// The "exit" command, which follows the "sleep" command,
// will close this console in 20 seconds
// But first let't test callback

"test_callback" callExtension """test data""";
  
sleep 20;

// BYE!
exit;