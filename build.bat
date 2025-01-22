msbuild /p:Configuration=Debug /p:Platform="x64" /t:Rebuild
msbuild /p:Configuration=Debug /p:Platform="x86" /t:Rebuild
msbuild /p:Configuration=Debug /p:Platform="arm64" /t:Rebuild
msbuild /p:Configuration=Release /p:Platform="x64" /t:Rebuild
msbuild /p:Configuration=Release /p:Platform="x86" /t:Rebuild
msbuild /p:Configuration=Release /p:Platform="arm64" /t:Rebuild