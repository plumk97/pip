cd /d "I:\Projects\pip\example_win\example_win" &msbuild "example_win.vcxproj" /t:sdvViewer /p:configuration="Debug" /p:platform="Win32" /p:SolutionDir="I:\Projects\pip\example_win" 
exit %errorlevel% 