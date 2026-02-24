@{
    ExcludeRules = @(
        'PSUseApprovedVerbs',
        'PSUseSingularNouns',
        'PSUseShouldProcessForStateChangingFunctions'
    )
    Rules = @{
        PSUseApprovedVerbs = @{ Enable = $false }
        PSUseSingularNouns = @{ Enable = $false }
        PSUseShouldProcessForStateChangingFunctions = @{ Enable = $false }
    }
}
