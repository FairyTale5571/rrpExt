// Test script "test_script2.sqf"
// Wait for 5 seconds then launch yet another script
sleep 5;

// Launch "test_script3.sqf"
execVM "test_script3.sqf";

// Resume "test_script2.sqf" script
// Wait for 5 seconds
sleep 5;

// End of "test_script2.sqf"