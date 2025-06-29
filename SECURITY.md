# Security Policy

## Supported Versions

We actively maintain and provide security updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | ✅ Yes             |
| < 1.0   | ❌ No              |

## Security Considerations

### Administrator Privileges

This tool requires administrator privileges to:
- Modify system registry entries
- Stop and disable Windows services
- Access system-level configuration files
- Clean up telemetry directories

**Important**: Only run this tool from trusted sources and review the code before execution.

### Registry Modifications

The tool modifies Windows Registry entries related to:
- Visual Studio telemetry settings
- Microsoft development tools configuration
- System-wide telemetry preferences

**Backup**: Always create registry backups before making changes using the `-CreateBackup` parameter.

### What This Tool Does NOT Do

- ❌ Does not create new registry keys unnecessarily
- ❌ Does not modify unrelated system settings
- ❌ Does not collect or transmit any data
- ❌ Does not install additional software
- ❌ Does not make network connections
- ❌ Does not access personal files or data

## Reporting a Vulnerability

If you discover a security vulnerability, please report it responsibly:

### How to Report

1. **Do NOT** open a public issue for security vulnerabilities
2. **Email** the maintainer directly at: [Your Email]
3. **Include** detailed information about the vulnerability:
   - Description of the issue
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment** within 48 hours
- **Initial assessment** within 7 days  
- **Regular updates** on progress
- **Credit** in security advisory (if desired)

### Response Timeline

- **Critical vulnerabilities**: Patch within 24-48 hours
- **High severity**: Patch within 7 days
- **Medium/Low severity**: Patch in next regular update

## Security Best Practices

### For Users

1. **Download from official sources**:
   - GitHub releases page
   - Official repository only

2. **Verify script integrity**:
   - Review code before running
   - Check file hashes if provided
   - Use virus scanning tools

3. **Run in controlled environment**:
   - Test on non-production systems first
   - Create system restore points
   - Create registry backups

4. **Use principle of least privilege**:
   - Only run when necessary
   - Review changes made
   - Monitor system behavior after execution

### For Developers

1. **Code review requirements**:
   - All code changes must be reviewed
   - Security implications must be assessed
   - No direct commits to main branch

2. **Input validation**:
   - Validate all user inputs
   - Sanitize file paths
   - Check registry path existence

3. **Error handling**:
   - Fail securely
   - Don't expose sensitive information
   - Log security-relevant events

## Threat Model

### Assets Protected
- User system configuration
- Registry integrity
- System stability
- User privacy settings

### Potential Threats
- Malicious modification of system settings
- Unauthorized privilege escalation
- Data corruption or loss
- Denial of service

### Mitigations
- Registry backup/restore functionality
- Path validation and sanitization
- Administrator privilege checks
- Comprehensive error handling
- Read-only operations where possible

## Security Features

### Built-in Protections

1. **Registry Backup System**:
   ```powershell
   # Creates timestamped backups
   .\off_telemetry_ps7.ps1 -CreateBackup
   
   # Restore if needed
   .\off_telemetry_ps7.ps1 -RestoreBackup -BackupPath "backup.reg"
   ```

2. **Path Validation**:
   - Only existing registry paths are modified
   - File system paths are validated
   - Administrative privileges are verified

3. **Safe Defaults**:
   - Conservative approach to system changes
   - Reversible operations
   - Clear status reporting

4. **Error Recovery**:
   - Graceful failure handling
   - Detailed error messages
   - Rollback capabilities

## Compliance

This tool aims to comply with:
- Windows security best practices
- PowerShell security guidelines
- Principle of least privilege
- Defense in depth strategy

## Updates and Patches

Security updates will be:
- Released as soon as possible
- Clearly marked in release notes
- Backwards compatible when possible
- Accompanied by migration guides if needed

## Additional Resources

- [Microsoft PowerShell Security](https://docs.microsoft.com/en-us/powershell/scripting/security/overview)
- [Windows Registry Security](https://docs.microsoft.com/en-us/windows/win32/sysinfo/registry-security-and-access-rights)
- [Windows Security Best Practices](https://docs.microsoft.com/en-us/windows/security/)

## Contact

For security-related questions or concerns:
- **Security issues**: [Your Security Email]
- **General questions**: Open an issue on GitHub
- **Documentation**: Refer to README.md

---

**Remember**: Security is a shared responsibility. Please use this tool responsibly and report any concerns promptly.