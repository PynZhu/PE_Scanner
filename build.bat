@echo off
cd /d e:\User\code\AI-Learning-CPP\PE_Scanner
echo Compiling...
if not exist obj mkdir obj

set INCLUDE=-IInclude -Ithird_party/duktape/src

g++ -std=c++17 %INCLUDE% -c Source\Core\Logger.cpp -o obj\Logger.o 2>obj\err.txt
if %ERRORLEVEL% NEQ 0 type obj\err.txt && exit /b 1
g++ -std=c++17 %INCLUDE% -c Source\Core\ErrorCodes.cpp -o obj\ErrorCodes.o 2>>obj\err.txt
if %ERRORLEVEL% NEQ 0 type obj\err.txt && exit /b 1
g++ -std=c++17 %INCLUDE% -c Source\Core\Localization.cpp -o obj\Localization.o 2>>obj\err.txt
if %ERRORLEVEL% NEQ 0 type obj\err.txt && exit /b 1
g++ -std=c++17 %INCLUDE% -c Source\Parsers\DosHeaderParser.cpp -o obj\DosHeaderParser.o 2>>obj\err.txt
if %ERRORLEVEL% NEQ 0 type obj\err.txt && exit /b 1
g++ -std=c++17 %INCLUDE% -c Source\Parsers\NtHeadersParser.cpp -o obj\NtHeadersParser.o 2>>obj\err.txt
if %ERRORLEVEL% NEQ 0 type obj\err.txt && exit /b 1
g++ -std=c++17 %INCLUDE% -c Source\Parsers\SectionParser.cpp -o obj\SectionParser.o 2>>obj\err.txt
if %ERRORLEVEL% NEQ 0 type obj\err.txt && exit /b 1
g++ -std=c++17 %INCLUDE% -c Source\Parsers\ImportTableParser.cpp -o obj\ImportTableParser.o 2>>obj\err.txt
if %ERRORLEVEL% NEQ 0 type obj\err.txt && exit /b 1
g++ -std=c++17 %INCLUDE% -c Source\Parsers\ExportTableParser.cpp -o obj\ExportTableParser.o 2>>obj\err.txt
if %ERRORLEVEL% NEQ 0 type obj\err.txt && exit /b 1
g++ -std=c++17 %INCLUDE% -c Source\Utils\FileMapper.cpp -o obj\FileMapper.o 2>>obj\err.txt
if %ERRORLEVEL% NEQ 0 type obj\err.txt && exit /b 1
g++ -std=c++17 %INCLUDE% -c Source\Utils\EntropyCalculator.cpp -o obj\EntropyCalculator.o 2>>obj\err.txt
if %ERRORLEVEL% NEQ 0 type obj\err.txt && exit /b 1
g++ -std=c++17 %INCLUDE% -c Source\Analyzers\AnalyzerManager.cpp -o obj\AnalyzerManager.o 2>>obj\err.txt
if %ERRORLEVEL% NEQ 0 type obj\err.txt && exit /b 1
g++ -std=c++17 %INCLUDE% -c Source\Analyzers\RiskAnalyzer.cpp -o obj\RiskAnalyzer.o 2>>obj\err.txt
if %ERRORLEVEL% NEQ 0 type obj\err.txt && exit /b 1
g++ -std=c++17 %INCLUDE% -c Source\Rules\DangerousAPIs.cpp -o obj\DangerousAPIs.o 2>>obj\err.txt
if %ERRORLEVEL% NEQ 0 type obj\err.txt && exit /b 1
g++ -std=c++17 %INCLUDE% -c Source\Rules\RuleEngine.cpp -o obj\RuleEngine.o 2>>obj\err.txt
if %ERRORLEVEL% NEQ 0 type obj\err.txt && exit /b 1
g++ -std=c++17 %INCLUDE% -c Source\Signatures\ScriptManager.cpp -o obj\ScriptManager.o 2>>obj\err.txt
if %ERRORLEVEL% NEQ 0 type obj\err.txt && exit /b 1
g++ -std=c++17 %INCLUDE% -c Source\PEAnalyzer.cpp -o obj\PEAnalyzer.o 2>>obj\err.txt
if %ERRORLEVEL% NEQ 0 type obj\err.txt && exit /b 1
g++ -std=c++17 %INCLUDE% -c Source\PE_Scanner.cpp -o obj\PE_Scanner.o 2>>obj\err.txt
if %ERRORLEVEL% NEQ 0 type obj\err.txt && exit /b 1

echo Compiling Duktape...
gcc -std=c11 %INCLUDE% -c third_party\duktape\src\duktape.c -o obj\duktape.o 2>>obj\err.txt
if %ERRORLEVEL% NEQ 0 type obj\err.txt && exit /b 1

echo Linking...
g++ -mconsole -municode obj\Logger.o obj\ErrorCodes.o obj\Localization.o obj\DosHeaderParser.o obj\NtHeadersParser.o obj\SectionParser.o obj\ImportTableParser.o obj\ExportTableParser.o obj\FileMapper.o obj\EntropyCalculator.o obj\AnalyzerManager.o obj\RiskAnalyzer.o obj\DangerousAPIs.o obj\RuleEngine.o obj\ScriptManager.o obj\PEAnalyzer.o obj\PE_Scanner.o obj\duktape.o -o test_build.exe -lm 2>>obj\err.txt
if %ERRORLEVEL% NEQ 0 type obj\err.txt && exit /b 1
echo BUILD_SUCCESS