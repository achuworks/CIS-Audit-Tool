from cx_Freeze import setup, Executable

setup(
    name="main2",
    version="1.0",
    description="Standalone App",
    options={
        "build_exe": {
            "zip_include_packages": ["*"], 
            "zip_exclude_packages": [],   
            "include_files": ["output3.csv", "test.ps1"],
        }
    },
    executables=[Executable("main2.py")])