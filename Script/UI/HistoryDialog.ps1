function Show-HistoryDialog {
    $form = New-Object System.Windows.Forms.Form
    $form.Text = L "History"
    $form.StartPosition = "CenterScreen"
    $form.FormBorderStyle = "Sizable"
    $form.ClientSize = New-Object System.Drawing.Size(760, 460)
    $form.MinimumSize = New-Object System.Drawing.Size(935, 590)
    $form.KeyPreview = $true

    $settings = $null
    if ($script:settings) {
        $settings = $script:settings
    } elseif ($script:Settings) {
        $settings = $script:Settings
    } else {
        $settingsVar = Get-Variable -Name settings -Scope Script -ErrorAction SilentlyContinue
        if ($settingsVar -and $settingsVar.Value) { $settings = $settingsVar.Value }
    }
    $historyView = Get-SettingsPropertyValue $settings "HistoryView"
    if ($historyView -isnot [hashtable]) { $historyView = Convert-ToHashtable $historyView }
    if (-not $historyView) {
        $historyView = @{
            Filter = "All"
            Search = ""
            AutoRefresh = $true
            SortColumn = 0
            SortAsc = $true
            Columns = @("Time", "Result", "Source", "Message")
            MaxRows = 200
            RelativeTime = $false
            PinFilters = $false
            WrapMessages = $true
            SourceFilter = "All"
        }
    }
    $currentFilter = [string]$historyView.Filter
    $sortColumn = [int]$historyView.SortColumn
    $sortAsc = [bool]$historyView.SortAsc
    $maxRows = [int]$historyView.MaxRows
    if (@("All", "Succeeded", "Failed") -notcontains $currentFilter) { $currentFilter = "All" }
    $useRelativeTime = [bool]$historyView.RelativeTime
    $pinFilters = [bool]$historyView.PinFilters
    $wrapMessages = [bool]$historyView.WrapMessages
    $sourceFilterValue = [string]$historyView.SourceFilter
    $historyInitializing = $true
    $historyWindowState = [string]$historyView.WindowState
    $historyWindowBounds = $historyView.WindowBounds

    $topPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $topPanel.Dock = "Top"
    $topPanel.AutoSize = $true
    $topPanel.WrapContents = $false
    $topPanel.FlowDirection = "TopDown"
    $topPanel.Padding = New-Object System.Windows.Forms.Padding(10, 8, 10, 0)

    $summaryLabel = New-Object System.Windows.Forms.Label
    $summaryLabel.AutoSize = $true
    $summaryLabel.Text = ((L "Total: {0}  Success: {1}  Fail: {2}") -f 0, 0, 0)
    $allLabel = L "All"

    $chipPanel = New-Object System.Windows.Forms.FlowLayoutPanel
    $chipPanel.FlowDirection = "LeftToRight"
    $chipPanel.AutoSize = $true
    $chipPanel.WrapContents = $false
    $chipPanel.Margin = New-Object System.Windows.Forms.Padding(18, 0, 0, 0)

    $newChip = {
        param([string]$text)
        $chip = New-Object System.Windows.Forms.Button
        $chip.Text = $text
        $chip.AutoSize = $true
        $chip.FlatStyle = "Flat"
        $chip.Margin = New-Object System.Windows.Forms.Padding(0, 0, 6, 0)
        $chip.BackColor = [System.Drawing.Color]::DimGray
        $chip.ForeColor = [System.Drawing.Color]::White
        return $chip
    }

    $chipAll = & $newChip $allLabel
    $chipSucceeded = & $newChip (L "Succeeded")
    $chipFailed = & $newChip (L "Failed")
    $chipPanel.Controls.Add($chipAll) | Out-Null
    $chipPanel.Controls.Add($chipSucceeded) | Out-Null
    $chipPanel.Controls.Add($chipFailed) | Out-Null

    $searchLabel = New-Object System.Windows.Forms.Label
    $searchLabel.AutoSize = $true
    $searchLabel.Text = L "Search:"
    $searchLabel.Margin = New-Object System.Windows.Forms.Padding(16, 3, 4, 0)

    $searchBox = New-Object System.Windows.Forms.TextBox
    $searchBox.Width = 180

    $searchClearButton = New-Object System.Windows.Forms.Button
    $searchClearButton.Text = L "Clear"
    $searchClearButton.Width = 50
    $searchClearButton.Margin = New-Object System.Windows.Forms.Padding(6, 0, 0, 0)
    $searchClearButton.Add_Click({ $searchBox.Text = "" })

    $resetButton = New-Object System.Windows.Forms.Button
    $resetButton.Text = L "Reset filters"
    $resetButton.AutoSize = $true
    $resetButton.Margin = New-Object System.Windows.Forms.Padding(10, 0, 0, 0)

    $liveBadge = New-Object System.Windows.Forms.Label
    $liveBadge.Text = "[ " + (L "Live Updates") + " ]"
    $liveBadge.AutoSize = $true
    $liveBadge.ForeColor = [System.Drawing.Color]::ForestGreen
    $liveBadge.BackColor = [System.Drawing.Color]::Transparent
    $liveBadge.Margin = New-Object System.Windows.Forms.Padding(8, 4, 0, 0)
    $liveBadge.Visible = $false

    $autoRefresh = New-Object System.Windows.Forms.CheckBox
    $autoRefresh.Text = L "Auto-refresh"
    $autoRefresh.AutoSize = $true
    $autoRefresh.Margin = New-Object System.Windows.Forms.Padding(0, 1, 0, 0)

    $relativeTimeBox = New-Object System.Windows.Forms.CheckBox
    $relativeTimeBox.Text = L "Relative time"
    $relativeTimeBox.AutoSize = $true
    $relativeTimeBox.Margin = New-Object System.Windows.Forms.Padding(12, 1, 0, 0)

    $pinFiltersBox = New-Object System.Windows.Forms.CheckBox
    $pinFiltersBox.Text = L "Pin filters"
    $pinFiltersBox.AutoSize = $true
    $pinFiltersBox.Margin = New-Object System.Windows.Forms.Padding(10, 1, 0, 0)

    $wrapMessagesBox = New-Object System.Windows.Forms.CheckBox
    $wrapMessagesBox.Text = L "Wrap message preview"
    $wrapMessagesBox.AutoSize = $true
    $wrapMessagesBox.Margin = New-Object System.Windows.Forms.Padding(10, 1, 0, 0)

    $sourceLabel = New-Object System.Windows.Forms.Label
    $sourceLabel.Text = L "Source:"
    $sourceLabel.AutoSize = $true
    $sourceLabel.Margin = New-Object System.Windows.Forms.Padding(12, 3, 4, 0)

    $sourceFilter = New-Object System.Windows.Forms.ComboBox
    $sourceFilter.DropDownStyle = "DropDownList"
    $sourceFilter.Width = 130
    [void]$sourceFilter.Items.Add($allLabel)
    $sourceFilter.SelectedIndex = 0

    $rowLimitLabel = New-Object System.Windows.Forms.Label
    $rowLimitLabel.Text = L "Rows:"
    $rowLimitLabel.AutoSize = $true
    $rowLimitLabel.Margin = New-Object System.Windows.Forms.Padding(12, 3, 4, 0)

    $rowLimitBox = New-Object System.Windows.Forms.ComboBox
    $rowLimitBox.DropDownStyle = "DropDownList"
    $rowLimitBox.Width = 70
    [void]$rowLimitBox.Items.AddRange(@("50", "100", "200", "500"))

    $jumpLatestButton = New-Object System.Windows.Forms.Button
    $jumpLatestButton.Text = L "Latest"
    $jumpLatestButton.AutoSize = $true
    $jumpLatestButton.Margin = New-Object System.Windows.Forms.Padding(12, 0, 0, 0)

    $jumpOldestButton = New-Object System.Windows.Forms.Button
    $jumpOldestButton.Text = L "Oldest"
    $jumpOldestButton.AutoSize = $true
    $jumpOldestButton.Margin = New-Object System.Windows.Forms.Padding(6, 0, 0, 0)

    $columnsButton = New-Object System.Windows.Forms.Button
    $columnsButton.Text = L "Columns"
    $columnsButton.AutoSize = $true
    $columnsButton.Margin = New-Object System.Windows.Forms.Padding(12, 0, 0, 0)

    $rowTwo = New-Object System.Windows.Forms.FlowLayoutPanel
    $rowTwo.FlowDirection = "LeftToRight"
    $rowTwo.AutoSize = $true
    $rowTwo.WrapContents = $false
    $rowTwo.Margin = New-Object System.Windows.Forms.Padding(10, 0, 10, 4)

    $rowTwo.Controls.Add($autoRefresh)
    $rowTwo.Controls.Add($relativeTimeBox)
    $rowTwo.Controls.Add($pinFiltersBox)
    $rowTwo.Controls.Add($wrapMessagesBox)
    $rowTwo.Controls.Add($sourceLabel)
    $rowTwo.Controls.Add($sourceFilter)
    $rowTwo.Controls.Add($rowLimitLabel)
    $rowTwo.Controls.Add($rowLimitBox)
    $rowTwo.Controls.Add($jumpLatestButton)
    $rowTwo.Controls.Add($jumpOldestButton)
    $rowTwo.Controls.Add($columnsButton)

    $rowOne = New-Object System.Windows.Forms.FlowLayoutPanel
    $rowOne.FlowDirection = "LeftToRight"
    $rowOne.AutoSize = $true
    $rowOne.WrapContents = $false
    $rowOne.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 4)

    $rowOne.Controls.Add($summaryLabel)
    $rowOne.Controls.Add($chipPanel)
    $rowOne.Controls.Add($searchLabel)
    $rowOne.Controls.Add($searchBox)
    $rowOne.Controls.Add($searchClearButton)
    $rowOne.Controls.Add($resetButton)
    $rowOne.Controls.Add($liveBadge)

    $topPanel.Controls.Add($rowOne)
    $topPanel.Controls.Add($rowTwo)

    $list = New-Object System.Windows.Forms.ListView
    $list.View = [System.Windows.Forms.View]::Details
    $list.FullRowSelect = $true
    $list.GridLines = $false
    $list.Dock = "Fill"
    $list.Font = New-Object System.Drawing.Font("Consolas", 9)
    $list.ShowGroups = $true
    [void]$list.Columns.Add((L "Time"), 170)
    [void]$list.Columns.Add((L "Result"), 80)
    [void]$list.Columns.Add((L "Source"), 120)
    [void]$list.Columns.Add((L "Message"), 340)

    $detailsPanel = New-Object System.Windows.Forms.Panel
    $detailsPanel.Dock = "Fill"
    $detailsPanel.Padding = New-Object System.Windows.Forms.Padding(8, 8, 8, 8)

    $detailsHeader = New-Object System.Windows.Forms.Label
    $detailsHeader.Text = L "Details"
    $detailsHeader.AutoSize = $true
    $detailsHeader.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
    $detailsHeader.Margin = New-Object System.Windows.Forms.Padding(0, 0, 0, 6)
    $detailsHeader.Dock = "Top"

    $detailsBox = New-Object System.Windows.Forms.TextBox
    $detailsBox.Multiline = $true
    $detailsBox.ReadOnly = $true
    $detailsBox.ScrollBars = "Vertical"
    $detailsBox.Dock = "Fill"
    $detailsBox.WordWrap = $true
    $detailsBox.Margin = New-Object System.Windows.Forms.Padding(0, 2, 0, 0)

    $detailsPanel.Controls.Add($detailsBox)
    $detailsPanel.Controls.Add($detailsHeader)

    $split = New-Object System.Windows.Forms.SplitContainer
    $split.Dock = "Fill"
    $split.Orientation = "Vertical"
    $split.SplitterDistance = 520
    $split.Panel1.Controls.Add($list)
    $split.Panel2.Controls.Add($detailsPanel)

    $columnWidths = @{
        Time = 170
        Result = 80
        Source = 120
        Message = 340
    }

    $columnsMenu = New-Object System.Windows.Forms.ContextMenuStrip
    $addColumnToggle = {
        param([string]$name, [int]$index)
        $item = New-Object System.Windows.Forms.ToolStripMenuItem((L $name))
        $item.CheckOnClick = $true
        $item.Checked = $true
        $item.Add_Click({
            if ($item.Checked) {
                $list.Columns[$index].Width = $columnWidths[$name]
            } else {
                $list.Columns[$index].Width = 0
            }
        })
        $columnsMenu.Items.Add($item) | Out-Null
        return $item
    }
    $columnItems = @{}
    $columnItems["Time"] = & $addColumnToggle "Time" 0
    $columnItems["Result"] = & $addColumnToggle "Result" 1
    $columnItems["Source"] = & $addColumnToggle "Source" 2
    $columnItems["Message"] = & $addColumnToggle "Message" 3
    $columnsButton.ContextMenuStrip = $columnsMenu
    $columnsButton.Add_Click({ $columnsMenu.Show($columnsButton, 0, $columnsButton.Height) })

    # Hover highlight disabled per request.

    if ($historyView.ContainsKey("Columns")) {
        foreach ($name in $columnItems.Keys) {
            $visible = @($historyView.Columns) -contains $name
            $columnItems[$name].Checked = $visible
            if ($visible) {
                $list.Columns[[int](@("Time","Result","Source","Message").IndexOf($name))].Width = $columnWidths[$name]
            } else {
                $list.Columns[[int](@("Time","Result","Source","Message").IndexOf($name))].Width = 0
            }
        }
    }

    if ($historyWindowBounds -and ($historyWindowBounds -is [hashtable])) {
        try {
            $x = [int]$historyWindowBounds.X
            $y = [int]$historyWindowBounds.Y
            $w = [int]$historyWindowBounds.Width
            $h = [int]$historyWindowBounds.Height
            if ($w -gt 0 -and $h -gt 0) {
                $form.StartPosition = "Manual"
                $form.Location = New-Object System.Drawing.Point($x, $y)
                $form.Size = New-Object System.Drawing.Size($w, $h)
            }
        } catch { }
    }
    if ($historyWindowState -eq "Maximized") { $form.WindowState = "Maximized" }

    $footerPanel = New-Object System.Windows.Forms.Panel
    $footerPanel.Dock = "Bottom"
    $footerPanel.Padding = New-Object System.Windows.Forms.Padding(10, 5, 10, 10)
    $footerPanel.Height = 50

    $footerLeft = New-Object System.Windows.Forms.FlowLayoutPanel
    $footerLeft.FlowDirection = "LeftToRight"
    $footerLeft.Dock = "Left"
    $footerLeft.AutoSize = $true
    $footerLeft.WrapContents = $false

    $footerRight = New-Object System.Windows.Forms.FlowLayoutPanel
    $footerRight.FlowDirection = "RightToLeft"
    $footerRight.Dock = "Right"
    $footerRight.AutoSize = $true
    $footerRight.WrapContents = $false

    $closeButton = New-Object System.Windows.Forms.Button
    $closeButton.Text = L "Close"
    $closeButton.Width = 90
    $closeButton.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

    $copyButton = New-Object System.Windows.Forms.Button
    $copyButton.Text = L "Copy"
    $copyButton.Width = 90

    $exportButton = New-Object System.Windows.Forms.Button
    $exportButton.Text = L "Export"
    $exportButton.Width = 90

    $clearButton = New-Object System.Windows.Forms.Button
    $clearButton.Text = L "Clear View"
    $clearButton.Width = 90

    $openLogsButton = New-Object System.Windows.Forms.Button
    $openLogsButton.Text = L "Open Logs Folder"
    $openLogsButton.Width = 130

    $footerRight.Controls.Add($closeButton)
    $footerRight.Controls.Add($clearButton)
    $footerRight.Controls.Add($exportButton)
    $footerRight.Controls.Add($copyButton)

    $footerLeft.Controls.Add($openLogsButton)

    $footerPanel.Controls.Add($footerLeft)
    $footerPanel.Controls.Add($footerRight)

    $form.Controls.Add($split)
    $form.Controls.Add($footerPanel)
    $form.Controls.Add($topPanel)
    $form.CancelButton = $closeButton

    $script:HistoryEvents = @()
    $script:HistoryFiltered = @()

    $parseEvents = {
        param([string[]]$lines)
        $result = @()
        foreach ($line in $lines) {
            if ($line -notmatch "Toggle (succeeded|failed)") { continue }
            $timestamp = ""
            $timestampValue = $null
            if ($line -match "^\[(?<ts>[^\]]+)\]") { $timestamp = $matches["ts"] }
            if ($timestamp) {
                $parsed = [datetime]::MinValue
                if ([datetime]::TryParse($timestamp, [ref]$parsed)) { $timestampValue = $parsed }
            }
            $outcome = if ($line -match "Toggle succeeded") { "Succeeded" } elseif ($line -match "Toggle failed") { "Failed" } else { "Unknown" }
            $source = ""
            if ($line -match "source=([^\)\s]+)") { $source = $matches[1] }
            $message = $line -replace '^\[[^\]]+\]\s*\[[A-Z]+\]\s*', ''
            $message = $message -replace '\[[A-Z][^]]*\]\s*', ''
            $result += [pscustomobject]@{
                Timestamp = $timestamp
                TimestampValue = $timestampValue
                Result = $outcome
                Source = $source
                Message = $message.Trim()
            }
        }
        return $result
    }

    $getRelativeTimeLabel = {
        param($dt, $raw)
        if (-not $useRelativeTime) { return $raw }
        if (-not $dt) { return $raw }
        $span = (Get-Date) - $dt
        if ($span.TotalSeconds -lt 60) { return (L "{0}s ago" -f [int]$span.TotalSeconds) }
        if ($span.TotalMinutes -lt 60) { return (L "{0}m ago" -f [int]$span.TotalMinutes) }
        if ($span.TotalHours -lt 24) { return (L "{0}h ago" -f [int]$span.TotalHours) }
        return (L "{0}d ago" -f [int]$span.TotalDays)
    }

    $autoSizeColumns = {
        for ($i = 0; $i -lt $list.Columns.Count; $i++) {
            if ($list.Columns[$i].Width -gt 0) { $list.Columns[$i].Width = -2 }
        }
    }

    $getDateGroupLabel = {
        param($dt, $raw)
        if ($dt) { return $dt.ToString("MMM dd, yyyy") }
        if ($raw) { return $raw }
        return (L "Unknown Date")
    }

    $applyFilter = {
        $filtered = $script:HistoryEvents
        if ($currentFilter -eq "Succeeded") {
            $filtered = $filtered | Where-Object { $_.Result -eq "Succeeded" }
        } elseif ($currentFilter -eq "Failed") {
            $filtered = $filtered | Where-Object { $_.Result -eq "Failed" }
        }
        $sourceValue = [string]$sourceFilter.SelectedItem
        if ($sourceValue -and $sourceValue -ne $allLabel) {
            $filtered = $filtered | Where-Object { $_.Source -eq $sourceValue }
        }
        $query = $searchBox.Text
        if ($query) {
            $filtered = $filtered | Where-Object {
                $_.Timestamp -like "*$query*" -or
                $_.Result -like "*$query*" -or
                $_.Source -like "*$query*" -or
                $_.Message -like "*$query*"
            }
        }

        $sortMap = @{ 0 = "TimestampValue"; 1 = "Result"; 2 = "Source"; 3 = "Message" }
        if ($sortMap.ContainsKey($sortColumn)) {
            if ($sortColumn -eq 0) {
                $filtered = $filtered | Sort-Object -Property @{ Expression = { if ($_.TimestampValue) { $_.TimestampValue } else { $_.Timestamp } } } -Descending:(-not $sortAsc)
            } else {
                $filtered = $filtered | Sort-Object -Property $sortMap[$sortColumn] -Descending:(-not $sortAsc)
            }
        }

        $list.BeginUpdate()
        $list.Items.Clear()
        $list.Groups.Clear()
        if (@($script:HistoryEvents).Count -eq 0) {
            $detailsBox.Text = L "No toggle history yet."
        } elseif (@($filtered).Count -eq 0) {
            $detailsBox.Text = L "No results match the current filter."
        } else {
            $groups = @{}
            foreach ($ev in $filtered) {
                $timeText = & $getRelativeTimeLabel $ev.TimestampValue $ev.Timestamp
                $resultIcon = if ($ev.Result -eq "Succeeded") { "[OK]" } elseif ($ev.Result -eq "Failed") { "[FAIL]" } else { "[?]" }
                $item = New-Object System.Windows.Forms.ListViewItem($timeText)
                [void]$item.SubItems.Add(($resultIcon + " " + $ev.Result))
                [void]$item.SubItems.Add($ev.Source)
                [void]$item.SubItems.Add($ev.Message)
                $groupLabel = & $getDateGroupLabel $ev.TimestampValue $ev.Timestamp
                if (-not $groups.ContainsKey($groupLabel)) {
                    $group = New-Object System.Windows.Forms.ListViewGroup($groupLabel, $groupLabel)
                    $list.Groups.Add($group) | Out-Null
                    $groups[$groupLabel] = $group
                }
                $item.Group = $groups[$groupLabel]
                [void]$list.Items.Add($item)
            }
        }
        $list.EndUpdate()

        & $autoSizeColumns

        $script:HistoryFiltered = $filtered
        $total = @($filtered).Count
        $success = @($filtered | Where-Object { $_.Result -eq "Succeeded" }).Count
        $fail = @($filtered | Where-Object { $_.Result -eq "Failed" }).Count
        $summaryLabel.Text = (L "Total: {0}  Success: {1}  Fail: {2}") -f $total, $success, $fail

        $chipAll.Text = (L "All ({0})" -f @($script:HistoryEvents).Count)
        $chipSucceeded.Text = (L "Succeeded ({0})" -f @($script:HistoryEvents | Where-Object { $_.Result -eq "Succeeded" }).Count)
        $chipFailed.Text = (L "Failed ({0})" -f @($script:HistoryEvents | Where-Object { $_.Result -eq "Failed" }).Count)
    }

    $setChipState = {
        param([string]$value)
        if ([string]::IsNullOrWhiteSpace($value)) { $value = "All" }
        $currentFilter = $value
        foreach ($chip in @($chipAll, $chipSucceeded, $chipFailed)) {
            $chip.BackColor = [System.Drawing.Color]::DimGray
        }
        switch ($value) {
            "Succeeded" { $chipSucceeded.BackColor = [System.Drawing.Color]::SeaGreen }
            "Failed" { $chipFailed.BackColor = [System.Drawing.Color]::Firebrick }
            default { $chipAll.BackColor = [System.Drawing.Color]::SteelBlue }
        }
        & $applyFilter
    }

    $chipAll.Add_Click({ & $setChipState "All" })
    $chipSucceeded.Add_Click({ & $setChipState "Succeeded" })
    $chipFailed.Add_Click({ & $setChipState "Failed" })

    $resetButton.Add_Click({
        $searchBox.Text = ""
        $autoRefresh.Checked = $true
        $sourceFilter.SelectedIndex = 0
        & $setChipState "All"
    })

    $relativeTimeBox.Add_CheckedChanged({
        $useRelativeTime = [bool]$relativeTimeBox.Checked
        & $applyFilter
    })

    $autoRefresh.Add_CheckedChanged({
        $liveBadge.Visible = [bool]$autoRefresh.Checked
    })

    $pinFiltersBox.Add_CheckedChanged({
        $pinFilters = [bool]$pinFiltersBox.Checked
        $chipAll.Enabled = -not $pinFilters
        $chipSucceeded.Enabled = -not $pinFilters
        $chipFailed.Enabled = -not $pinFilters
        $searchBox.ReadOnly = $pinFilters
        $resetButton.Enabled = -not $pinFilters
        $sourceFilter.Enabled = -not $pinFilters
        $rowLimitBox.Enabled = -not $pinFilters
    })

    $wrapMessagesBox.Add_CheckedChanged({
        $wrapMessages = [bool]$wrapMessagesBox.Checked
        $detailsBox.WordWrap = $wrapMessages
        if (-not $wrapMessages) { $detailsBox.ScrollBars = "Vertical" } else { $detailsBox.ScrollBars = "Vertical" }
    })

    $form.Add_KeyDown({
        if ($_.Control -and $_.KeyCode -eq [System.Windows.Forms.Keys]::F) {
            $searchBox.Focus()
            $searchBox.SelectAll()
            $_.Handled = $true
            return
        }
        if ($_.Control -and $_.KeyCode -eq [System.Windows.Forms.Keys]::C) {
            if ($copyButton) { $copyButton.PerformClick() }
            $_.Handled = $true
            return
        }
        if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Escape) {
            $form.Close()
            $_.Handled = $true
            return
        }
    })

    $sourceFilter.Add_SelectedIndexChanged({ & $applyFilter })
    $rowLimitBox.Add_SelectedIndexChanged({
        if ($historyInitializing) { return }
        $newLimit = 0
        if ([int]::TryParse([string]$rowLimitBox.SelectedItem, [ref]$newLimit)) {
            $maxRows = $newLimit
            & $loadHistory
        }
    })

    $jumpLatestButton.Add_Click({
        if ($list.Items.Count -eq 0) { return }
        $last = $list.Items[$list.Items.Count - 1]
        $last.EnsureVisible()
        $last.Selected = $true
    })

    $jumpOldestButton.Add_Click({
        if ($list.Items.Count -eq 0) { return }
        $first = $list.Items[0]
        $first.EnsureVisible()
        $first.Selected = $true
    })

    $list.Add_ColumnClick({
        param($sender, $e)
        if ($sortColumn -eq $e.Column) {
            $sortAsc = -not $sortAsc
        } else {
            $sortColumn = $e.Column
            $sortAsc = $true
        }
        & $applyFilter
    })

    $list.Add_SelectedIndexChanged({
        if ($list.SelectedItems.Count -eq 0) { $detailsBox.Text = ""; return }
        $item = $list.SelectedItems[0]
        if ($item.SubItems.Count -lt 4) { $detailsBox.Text = ""; return }
        $detailsBox.Text = ((L "Time: {0}`r`nResult: {1}`r`nSource: {2}`r`nMessage: {3}") -f $item.Text, $item.SubItems[1].Text, $item.SubItems[2].Text, $item.SubItems[3].Text)
    })

    $contextMenu = New-Object System.Windows.Forms.ContextMenuStrip
    $ctxCopyRow = New-Object System.Windows.Forms.ToolStripMenuItem((L "Copy row"))
    $ctxCopyMessage = New-Object System.Windows.Forms.ToolStripMenuItem((L "Copy message"))
    $ctxOpenLogs = New-Object System.Windows.Forms.ToolStripMenuItem((L "Open Logs Folder"))
    $contextMenu.Items.Add($ctxCopyRow) | Out-Null
    $contextMenu.Items.Add($ctxCopyMessage) | Out-Null
    $contextMenu.Items.Add($ctxOpenLogs) | Out-Null
    $list.ContextMenuStrip = $contextMenu

    $ctxCopyRow.Add_Click({
        if ($list.SelectedItems.Count -eq 0) { return }
        $item = $list.SelectedItems[0]
        $cols = @($item.Text)
        for ($i = 1; $i -lt $item.SubItems.Count; $i++) { $cols += $item.SubItems[$i].Text }
        try { Set-Clipboard -Value ($cols -join "`t") } catch { }
    })

    $ctxCopyMessage.Add_Click({
        if ($list.SelectedItems.Count -eq 0) { return }
        $item = $list.SelectedItems[0]
        if ($item.SubItems.Count -ge 4) {
            try { Set-Clipboard -Value $item.SubItems[3].Text } catch { }
        }
    })

    $ctxOpenLogs.Add_Click({
        try { Start-Process $script:LogDirectory } catch { }
    })

    $searchBox.Text = [string]$historyView.Search
    $autoRefresh.Checked = [bool]$historyView.AutoRefresh
    $liveBadge.Visible = [bool]$autoRefresh.Checked
    $relativeTimeBox.Checked = $useRelativeTime
    $pinFiltersBox.Checked = $pinFilters
    $wrapMessagesBox.Checked = $wrapMessages
    $rowLimitBox.SelectedItem = [string]$maxRows
    & $setChipState $currentFilter
    $script:HistoryLastLogWrite = $null
    $script:HistoryLastLogSize = $null

    $loadHistory = {
        param([bool]$force = $false)
        try {
            if (-not (Test-Path $logPath)) {
                "" | Set-Content -Path $logPath -Encoding UTF8
            }
            if (-not $force) {
                try {
                    $info = Get-Item -Path $logPath -ErrorAction SilentlyContinue
                    if ($info) {
                        if ($script:HistoryLastLogWrite -and $script:HistoryLastLogSize -ne $null) {
                            if ($info.LastWriteTime -eq $script:HistoryLastLogWrite -and $info.Length -eq $script:HistoryLastLogSize) {
                                return
                            }
                        }
                        $script:HistoryLastLogWrite = $info.LastWriteTime
                        $script:HistoryLastLogSize = $info.Length
                    }
                } catch {
                }
            }
            $lines = Get-Content -Path $logPath -Tail 2000
            $take = if ($maxRows -gt 0) { $maxRows } else { 200 }
            $script:HistoryEvents = & $parseEvents $lines | Select-Object -Last $take
            $sources = @($script:HistoryEvents | Where-Object { -not [string]::IsNullOrWhiteSpace($_.Source) } | Select-Object -ExpandProperty Source -Unique | Sort-Object)
            $current = [string]$sourceFilter.SelectedItem
            $sourceFilter.Items.Clear()
            [void]$sourceFilter.Items.Add($allLabel)
            foreach ($s in $sources) { [void]$sourceFilter.Items.Add($s) }
            if ($current -and $sourceFilter.Items.Contains($current)) {
                $sourceFilter.SelectedItem = $current
            } elseif ($current -eq "All" -or $current -eq $allLabel) {
                $sourceFilter.SelectedItem = $allLabel
            } else {
                $sourceFilter.SelectedIndex = 0
            }
        } catch {
            $script:HistoryEvents = @()
            Write-Log "Failed to load history." "ERROR" $_.Exception "History"
        }
        & $applyFilter
    }

    $copyButton.Add_Click({
        $items = if ($list.SelectedItems.Count -gt 0) { $list.SelectedItems } else { @() }
        if ($items.Count -eq 0 -and $script:HistoryFiltered) {
            $items = @()
            foreach ($ev in $script:HistoryFiltered) {
                $item = New-Object System.Windows.Forms.ListViewItem($ev.Timestamp)
                [void]$item.SubItems.Add($ev.Result)
                [void]$item.SubItems.Add($ev.Source)
                [void]$item.SubItems.Add($ev.Message)
                $items += $item
            }
        }
        if ($items.Count -eq 0) { return }
        $lines = @()
        $lines += "Time`tResult`tSource`tMessage"
        foreach ($item in $items) {
            $cols = @($item.Text)
            for ($i = 1; $i -lt $item.SubItems.Count; $i++) {
                $cols += $item.SubItems[$i].Text
            }
            $lines += ($cols -join "`t")
        }
        try { Set-Clipboard -Value ($lines -join "`r`n") } catch { }
    })

    $exportButton.Add_Click({
        $dialog = New-Object System.Windows.Forms.SaveFileDialog
        $dialog.Filter = "Text Files (*.txt)|*.txt|CSV Files (*.csv)|*.csv|All Files (*.*)|*.*"
        $dialog.FileName = "Teams-Always-Green.history.txt"
        if ($dialog.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return }
        $items = if ($list.SelectedItems.Count -gt 0) { $list.SelectedItems } else { @() }
        if ($items.Count -eq 0 -and $script:HistoryFiltered) {
            $items = @()
            foreach ($ev in $script:HistoryFiltered) {
                $item = New-Object System.Windows.Forms.ListViewItem($ev.Timestamp)
                [void]$item.SubItems.Add($ev.Result)
                [void]$item.SubItems.Add($ev.Source)
                [void]$item.SubItems.Add($ev.Message)
                $items += $item
            }
        }
        if ($items.Count -eq 0) { return }
        $lines = @()
        $ext = [System.IO.Path]::GetExtension($dialog.FileName)
        if ($ext -ieq ".csv") {
            $lines += ((L "Time") + "," + (L "Result") + "," + (L "Source") + "," + (L "Message"))
            foreach ($item in $items) {
                $cols = @($item.Text)
                for ($i = 1; $i -lt $item.SubItems.Count; $i++) {
                    $cols += $item.SubItems[$i].Text
                }
                $escaped = $cols | ForEach-Object { '"' + (($_ -replace '"', '""')) + '"' }
                $lines += ($escaped -join ",")
            }
        } else {
            $lines += ((L "Time") + "`t" + (L "Result") + "`t" + (L "Source") + "`t" + (L "Message"))
            foreach ($item in $items) {
                $cols = @($item.Text)
                for ($i = 1; $i -lt $item.SubItems.Count; $i++) {
                    $cols += $item.SubItems[$i].Text
                }
                $lines += ($cols -join "`t")
            }
        }
        try { Set-Content -Path $dialog.FileName -Value $lines -Encoding UTF8 } catch { }
    })

    $clearButton.Add_Click({
        $result = [System.Windows.Forms.MessageBox]::Show(
            $form,
            (L "Clear the current History view? This will not delete the log file."),
            (L "Clear History View"),
            [System.Windows.Forms.MessageBoxButtons]::YesNo,
            [System.Windows.Forms.MessageBoxIcon]::Question
        )
        if ($result -ne [System.Windows.Forms.DialogResult]::Yes) { return }
        $script:HistoryEvents = @()
        $script:HistoryFiltered = @()
        & $applyFilter
        $detailsBox.Text = ""
    })

    $openLogsButton.Add_Click({
        try {
            if (-not (Test-Path $script:LogDirectory)) {
                Ensure-Directory $script:LogDirectory "Logs" | Out-Null
            }
            Start-Process -FilePath explorer.exe -ArgumentList ("`"{0}`"" -f $script:LogDirectory)
        } catch {
        }
    })

    $searchBox.Add_TextChanged({ & $applyFilter })

    $refreshTimer = New-Object System.Windows.Forms.Timer
    $refreshTimer.Interval = 2000
    $refreshTimer.Add_Tick({
        Invoke-SafeTimerAction "HistoryRefreshTimer" {
            if (-not $autoRefresh.Checked) { return }
            if (-not $form.Visible -or $form.WindowState -eq [System.Windows.Forms.FormWindowState]::Minimized) { return }
            & $loadHistory $false
        }
    })
    $form.Add_FormClosing({
        try { $refreshTimer.Stop() } catch { }
        try {
            $historyView["Filter"] = $currentFilter
            $historyView["Search"] = $searchBox.Text
            $historyView["AutoRefresh"] = [bool]$autoRefresh.Checked
            $historyView["SortColumn"] = $sortColumn
            $historyView["SortAsc"] = $sortAsc
            $historyView["MaxRows"] = $maxRows
            $historyView["RelativeTime"] = [bool]$relativeTimeBox.Checked
            $historyView["PinFilters"] = [bool]$pinFiltersBox.Checked
            $historyView["WrapMessages"] = [bool]$wrapMessagesBox.Checked
            $selectedSource = [string]$sourceFilter.SelectedItem
            if ($selectedSource -eq $allLabel) {
                $historyView["SourceFilter"] = "All"
            } else {
                $historyView["SourceFilter"] = $selectedSource
            }
            $historyView["WindowState"] = [string]$form.WindowState
            if ($form.WindowState -eq [System.Windows.Forms.FormWindowState]::Normal) {
                $historyView["WindowBounds"] = @{
                    X = $form.Location.X
                    Y = $form.Location.Y
                    Width = $form.Size.Width
                    Height = $form.Size.Height
                }
            }
            $visibleColumns = @()
            foreach ($name in $columnItems.Keys) {
                if ($columnItems[$name].Checked) { $visibleColumns += $name }
            }
            if ($visibleColumns.Count -gt 0) { $historyView["Columns"] = $visibleColumns }
            Set-SettingsPropertyValue $settings "HistoryView" $historyView
            Save-Settings $settings -Immediate
        } catch { }
    })
    $refreshTimer.Start()

    & $loadHistory $true
    if ($sourceFilterValue) {
        if ($sourceFilterValue -eq "All") {
            $sourceFilter.SelectedItem = $allLabel
        } elseif ($sourceFilter.Items.Contains($sourceFilterValue)) {
            $sourceFilter.SelectedItem = $sourceFilterValue
        }
    }
    $historyInitializing = $false

    Update-ThemePreference
    Apply-ThemeToControl $form $script:ThemePalette $script:UseDarkTheme
    try {
        if ($liveBadge) {
            $liveBadge.BackColor = [System.Drawing.Color]::Transparent
            $liveBadge.ForeColor = [System.Drawing.Color]::ForestGreen
        }
    } catch { }

    [void]$form.ShowDialog()
}
