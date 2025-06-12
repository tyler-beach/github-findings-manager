package reports

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/xuri/excelize/v2"
	"github.com/sirupsen/logrus"

	"github_findings_manager/pkg/models"
)

// GenerateExcelReport creates a comprehensive Excel report with multiple sheets
func (r *Reporter) GenerateExcelReport(results *models.CollectionResults) error {
	filename := fmt.Sprintf("github_findings_%s_%s.xlsx", 
		results.Organization, 
		results.CollectedAt.Format("2006-01-02_15-04-05"))
	filepath := filepath.Join(r.config.OutputDir, filename)

	f := excelize.NewFile()
	defer f.Close()

	// Create sheets
	if err := r.createFindingsSheet(f, results); err != nil {
		return fmt.Errorf("failed to create findings sheet: %w", err)
	}

	if err := r.createSummarySheet(f, results); err != nil {
		return fmt.Errorf("failed to create summary sheet: %w", err)
	}

	if err := r.createRepositorySheet(f, results); err != nil {
		return fmt.Errorf("failed to create repository sheet: %w", err)
	}

	if err := r.createTimelineSheet(f, results); err != nil {
		return fmt.Errorf("failed to create timeline sheet: %w", err)
	}

	if err := r.createPivotDashboard(f, results); err != nil {
		return fmt.Errorf("failed to create pivot dashboard: %w", err)
	}

	// Delete the default sheet
	f.DeleteSheet("Sheet1")

	// Save the file
	if err := f.SaveAs(filepath); err != nil {
		return fmt.Errorf("failed to save Excel file: %w", err)
	}

	logrus.Infof("Excel report saved to: %s", filepath)
	return nil
}

// createFindingsSheet creates the main findings data sheet
func (r *Reporter) createFindingsSheet(f *excelize.File, results *models.CollectionResults) error {
	sheetName := "Findings"
	_, err := f.NewSheet(sheetName)
	if err != nil {
		return err
	}

	// Headers
	headers := []string{
		"Repository", "Finding Type", "Severity", "State", "Title", 
		"Created Date", "Updated Date", "Pod", "Attribution", "Quarter", 
		"URL", "Rule ID", "Secret Type", "Package Name", "Vulnerable Version Range",
	}

	// Write headers
	for i, header := range headers {
		cell := fmt.Sprintf("%c1", 'A'+i)
		f.SetCellValue(sheetName, cell, header)
	}

	// Style headers
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Color: "FFFFFF"},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"366092"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center"},
	})
	f.SetCellStyle(sheetName, "A1", fmt.Sprintf("%c1", 'A'+len(headers)-1), headerStyle)

	// Write data
	for i, finding := range results.Findings {
		row := i + 2
		f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), finding.Repository)
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), finding.Type)
		f.SetCellValue(sheetName, fmt.Sprintf("C%d", row), finding.Severity)
		f.SetCellValue(sheetName, fmt.Sprintf("D%d", row), finding.State)
		f.SetCellValue(sheetName, fmt.Sprintf("E%d", row), finding.Title)
		f.SetCellValue(sheetName, fmt.Sprintf("F%d", row), finding.CreatedAt.Format("2006-01-02"))
		f.SetCellValue(sheetName, fmt.Sprintf("G%d", row), finding.UpdatedAt.Format("2006-01-02"))
		f.SetCellValue(sheetName, fmt.Sprintf("H%d", row), finding.Pod)
		f.SetCellValue(sheetName, fmt.Sprintf("I%d", row), finding.Attribution)
		f.SetCellValue(sheetName, fmt.Sprintf("J%d", row), finding.Quarter)
		f.SetCellValue(sheetName, fmt.Sprintf("K%d", row), finding.URL)
		f.SetCellValue(sheetName, fmt.Sprintf("L%d", row), finding.RuleID)
		f.SetCellValue(sheetName, fmt.Sprintf("M%d", row), finding.SecretType)
		f.SetCellValue(sheetName, fmt.Sprintf("N%d", row), finding.PackageName)
		f.SetCellValue(sheetName, fmt.Sprintf("O%d", row), finding.VulnerableVersionRange)
	}

	// Auto-fit columns
	for i := range headers {
		col := fmt.Sprintf("%c:%c", 'A'+i, 'A'+i)
		f.SetColWidth(sheetName, col, col, 15)
	}

	// Add table formatting
	if len(results.Findings) > 0 {
		tableRange := fmt.Sprintf("A1:O%d", len(results.Findings)+1)
		f.AddTable(sheetName, &excelize.Table{
			Range:     tableRange,
			Name:      "FindingsTable",
			StyleName: "TableStyleMedium9",
		})
	}

	return nil
}

// createSummarySheet creates the summary statistics sheet
func (r *Reporter) createSummarySheet(f *excelize.File, results *models.CollectionResults) error {
	sheetName := "Summary"
	_, err := f.NewSheet(sheetName)
	if err != nil {
		return err
	}

	// Title
	f.SetCellValue(sheetName, "A1", "GitHub Security Findings Summary")
	titleStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Size: 16},
	})
	f.SetCellStyle(sheetName, "A1", "A1", titleStyle)

	row := 3

	// Organization info
	f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), "Organization:")
	f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), results.Organization)
	row++

	f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), "Collection Date:")
	f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), results.CollectedAt.Format("2006-01-02 15:04:05"))
	row += 2

	// Overall statistics
	f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), "Overall Statistics")
	headerStyle, _ := f.NewStyle(&excelize.Style{Font: &excelize.Font{Bold: true}})
	f.SetCellStyle(sheetName, fmt.Sprintf("A%d", row), fmt.Sprintf("A%d", row), headerStyle)
	row++

	stats := [][]interface{}{
		{"Total Repositories:", len(results.Repositories)},
		{"Total Findings:", len(results.Findings)},
		{"Code Scanning Findings:", results.Stats.CodeScanningFindings},
		{"Secret Scanning Findings:", results.Stats.SecretsFindings},
		{"Dependabot Findings:", results.Stats.DependabotFindings},
		{"Attributed Findings:", results.Stats.AttributedFindings},
		{"Unattributed Findings:", results.Stats.UnattributedFindings},
		{"API Calls Made:", results.Stats.APICallsTotal},
		{"Collection Duration:", results.Stats.Duration.String()},
	}

	for _, stat := range stats {
		f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), stat[0])
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), stat[1])
		row++
	}

	row += 2

	// Findings by type with attribution breakdown
	f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), "Findings by Type")
	f.SetCellStyle(sheetName, fmt.Sprintf("A%d", row), fmt.Sprintf("A%d", row), headerStyle)
	row++

	// Headers for the attribution breakdown table
	f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), "Finding Type")
	f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), "Total")
	f.SetCellValue(sheetName, fmt.Sprintf("C%d", row), "Attributed")
	f.SetCellValue(sheetName, fmt.Sprintf("D%d", row), "Unattributed")
	f.SetCellValue(sheetName, fmt.Sprintf("E%d", row), "Attribution %")
	
	// Style the sub-headers
	subHeaderStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"E7E6E6"}, Pattern: 1},
	})
	f.SetCellStyle(sheetName, fmt.Sprintf("A%d", row), fmt.Sprintf("E%d", row), subHeaderStyle)
	row++

	// Calculate attribution breakdown by type
	findingsByType := results.GetFindingsByType()
	typeOrder := []string{"code_scanning", "secrets", "dependabot"} // Ensure consistent order
	
	for _, findingType := range typeOrder {
		findings, exists := findingsByType[findingType]
		if !exists {
			continue
		}
		
		attributed := 0
		unattributed := 0
		
		for _, finding := range findings {
			if finding.Pod != "No Pod Selected" {
				attributed++
			} else {
				unattributed++
			}
		}
		
		total := len(findings)
		attributionPercentage := calculatePercentage(attributed, total)
		
		// Format the finding type name
		typeName := findingType
		switch findingType {
		case "code_scanning":
			typeName = "Code Scanning"
		case "secrets":
			typeName = "Secret Scanning"
		case "dependabot":
			typeName = "Dependabot"
		}
		
		f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), typeName)
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), total)
		f.SetCellValue(sheetName, fmt.Sprintf("C%d", row), attributed)
		f.SetCellValue(sheetName, fmt.Sprintf("D%d", row), unattributed)
		f.SetCellValue(sheetName, fmt.Sprintf("E%d", row), attributionPercentage)
		row++
	}

	row += 2

	// Findings by pod
	f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), "Findings by Pod")
	f.SetCellStyle(sheetName, fmt.Sprintf("A%d", row), fmt.Sprintf("A%d", row), headerStyle)
	row++

	findingsByPod := results.GetFindingsByPod()
	for pod, findings := range findingsByPod {
		f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), pod)
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), len(findings))
		row++
	}

	return nil
}

// createRepositorySheet creates the repository information sheet
func (r *Reporter) createRepositorySheet(f *excelize.File, results *models.CollectionResults) error {
	sheetName := "Repositories"
	_, err := f.NewSheet(sheetName)
	if err != nil {
		return err
	}

	// Headers
	headers := []string{
		"Repository", "Pod", "Environment Type", "Code Scanning", 
		"Secret Scanning", "Dependabot", "Access Errors",
	}

	// Write headers
	for i, header := range headers {
		cell := fmt.Sprintf("%c1", 'A'+i)
		f.SetCellValue(sheetName, cell, header)
	}

	// Style headers
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Color: "FFFFFF"},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"366092"}, Pattern: 1},
	})
	f.SetCellStyle(sheetName, "A1", fmt.Sprintf("%c1", 'A'+len(headers)-1), headerStyle)

	// Write repository data
	row := 2
	for _, repo := range results.Repositories {
		f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), repo.Name)
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), repo.Pod)
		f.SetCellValue(sheetName, fmt.Sprintf("C%d", row), repo.EnvironmentType)
		f.SetCellValue(sheetName, fmt.Sprintf("D%d", row), boolToYesNo(repo.CodeScanningEnabled))
		f.SetCellValue(sheetName, fmt.Sprintf("E%d", row), boolToYesNo(repo.SecretsEnabled))
		f.SetCellValue(sheetName, fmt.Sprintf("F%d", row), boolToYesNo(repo.DependabotEnabled))
		
		errorStr := ""
		if len(repo.AccessErrors) > 0 {
			errorStr = repo.AccessErrors[0] // Show first error
		}
		f.SetCellValue(sheetName, fmt.Sprintf("G%d", row), errorStr)
		row++
	}

	// Auto-fit columns
	for i := range headers {
		col := fmt.Sprintf("%c:%c", 'A'+i, 'A'+i)
		f.SetColWidth(sheetName, col, col, 15)
	}

	return nil
}

// createTimelineSheet creates the enhanced timeline analysis sheet with attribution breakdown and charts
func (r *Reporter) createTimelineSheet(f *excelize.File, results *models.CollectionResults) error {
	sheetName := "Timeline"
	_, err := f.NewSheet(sheetName)
	if err != nil {
		return err
	}

	// Group findings by quarter
	findingsByQuarter := results.GetFindingsByQuarter()
	
	// Sort quarters
	var quarters []string
	for quarter := range findingsByQuarter {
		quarters = append(quarters, quarter)
	}
	sort.Strings(quarters)

	// Enhanced headers for detailed attribution breakdown
	headers := []string{
		"Quarter", "Total Findings", 
		"Code Scan (Attributed)", "Code Scan (Unattributed)",
		"Secret Scan (Attributed)", "Secret Scan (Unattributed)", 
		"Dependabot (Attributed)", "Dependabot (Unattributed)",
		"Total Attributed", "Total Unattributed",
	}

	// Write headers
	for i, header := range headers {
		cell := fmt.Sprintf("%c1", 'A'+i)
		f.SetCellValue(sheetName, cell, header)
	}

	// Style headers
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Color: "FFFFFF"},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"366092"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center", WrapText: true},
	})
	f.SetCellStyle(sheetName, "A1", fmt.Sprintf("%c1", 'A'+len(headers)-1), headerStyle)

	// Set column widths
	f.SetColWidth(sheetName, "A", "A", 12) // Quarter
	f.SetColWidth(sheetName, "B", "B", 14) // Total Findings  
	f.SetColWidth(sheetName, "C", "H", 16) // Attribution columns
	f.SetColWidth(sheetName, "I", "J", 14) // Totals

	// Write detailed timeline data
	for i, quarter := range quarters {
		row := i + 2
		findings := findingsByQuarter[quarter]
		
		// Count findings by type and attribution
		var (
			codeScanAttr, codeScanUnattr       int
			secretScanAttr, secretScanUnattr   int
			dependabotAttr, dependabotUnattr   int
			totalAttr, totalUnattr             int
		)

		for _, finding := range findings {
			isAttributed := finding.Pod != "No Pod Selected"
			
			switch finding.Type {
			case "code_scanning":
				if isAttributed {
					codeScanAttr++
				} else {
					codeScanUnattr++
				}
			case "secrets":
				if isAttributed {
					secretScanAttr++
				} else {
					secretScanUnattr++
				}
			case "dependabot":
				if isAttributed {
					dependabotAttr++
				} else {
					dependabotUnattr++
				}
			}

			if isAttributed {
				totalAttr++
			} else {
				totalUnattr++
			}
		}

		// Write data
		f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), quarter)
		f.SetCellValue(sheetName, fmt.Sprintf("B%d", row), len(findings))
		f.SetCellValue(sheetName, fmt.Sprintf("C%d", row), codeScanAttr)
		f.SetCellValue(sheetName, fmt.Sprintf("D%d", row), codeScanUnattr)
		f.SetCellValue(sheetName, fmt.Sprintf("E%d", row), secretScanAttr)
		f.SetCellValue(sheetName, fmt.Sprintf("F%d", row), secretScanUnattr)
		f.SetCellValue(sheetName, fmt.Sprintf("G%d", row), dependabotAttr)
		f.SetCellValue(sheetName, fmt.Sprintf("H%d", row), dependabotUnattr)
		f.SetCellValue(sheetName, fmt.Sprintf("I%d", row), totalAttr)
		f.SetCellValue(sheetName, fmt.Sprintf("J%d", row), totalUnattr)
	}

	// Add trending charts
	if len(quarters) > 1 {
		if err := r.createTimelineCharts(f, sheetName, len(quarters)); err != nil {
			// Log error but don't fail the sheet creation
			fmt.Printf("Warning: Could not create timeline charts: %v\n", err)
		}
	}

	// Add summary section below the data
	summaryRow := len(quarters) + 4
	f.SetCellValue(sheetName, fmt.Sprintf("A%d", summaryRow), "Attribution Summary")
	f.SetCellStyle(sheetName, fmt.Sprintf("A%d", summaryRow), fmt.Sprintf("A%d", summaryRow), headerStyle)

	summaryRow += 2
	r.createAttributionSummary(f, sheetName, summaryRow, results)

	return nil
}

// createTimelineCharts creates charts for timeline trends
func (r *Reporter) createTimelineCharts(f *excelize.File, sheetName string, dataRows int) error {
	chartRow := dataRows + 6

	// Chart 1: Total Attributed vs Unattributed Trend (Line Chart)
	err := f.AddChart(sheetName, fmt.Sprintf("L%d", chartRow), &excelize.Chart{
		Type: excelize.Line,
		Series: []excelize.ChartSeries{
			{
				Name:       "Attributed Findings",
				Categories: fmt.Sprintf("%s!$A$2:$A$%d", sheetName, dataRows+1),
				Values:     fmt.Sprintf("%s!$I$2:$I$%d", sheetName, dataRows+1),
			},
			{
				Name:       "Unattributed Findings", 
				Categories: fmt.Sprintf("%s!$A$2:$A$%d", sheetName, dataRows+1),
				Values:     fmt.Sprintf("%s!$J$2:$J$%d", sheetName, dataRows+1),
			},
		},
		PlotArea: excelize.ChartPlotArea{
			ShowCatName:     false,
			ShowLeaderLines: false,
			ShowPercent:     false,
			ShowSerName:     true,
			ShowVal:         false,
		},
		ShowBlanksAs: "gap",
		Dimension: excelize.ChartDimension{
			Width:  640,
			Height: 320,
		},
	})
	if err != nil {
		// Log error but don't fail the sheet creation
		fmt.Printf("Warning: Could not create attribution trend chart: %v\n", err)
	}

	// Chart 2: Finding Types Attribution Breakdown (Column Chart)
	chart2Row := chartRow + 22
	err = f.AddChart(sheetName, fmt.Sprintf("L%d", chart2Row), &excelize.Chart{
		Type: excelize.Col,
		Series: []excelize.ChartSeries{
			{
				Name:       "Code Scanning (Attributed)",
				Categories: fmt.Sprintf("%s!$A$2:$A$%d", sheetName, dataRows+1),
				Values:     fmt.Sprintf("%s!$C$2:$C$%d", sheetName, dataRows+1),
				Fill:       excelize.Fill{Color: []string{"70AD47"}},
			},
			{
				Name:       "Code Scanning (Unattributed)",
				Categories: fmt.Sprintf("%s!$A$2:$A$%d", sheetName, dataRows+1),
				Values:     fmt.Sprintf("%s!$D$2:$D$%d", sheetName, dataRows+1),
				Fill:       excelize.Fill{Color: []string{"FFC000"}},
			},
			{
				Name:       "Secret Scanning (Attributed)",
				Categories: fmt.Sprintf("%s!$A$2:$A$%d", sheetName, dataRows+1),
				Values:     fmt.Sprintf("%s!$E$2:$E$%d", sheetName, dataRows+1),
				Fill:       excelize.Fill{Color: []string{"5B9BD5"}},
			},
			{
				Name:       "Secret Scanning (Unattributed)",
				Categories: fmt.Sprintf("%s!$A$2:$A$%d", sheetName, dataRows+1),
				Values:     fmt.Sprintf("%s!$F$2:$F$%d", sheetName, dataRows+1),
				Fill:       excelize.Fill{Color: []string{"A5A5A5"}},
			},
			{
				Name:       "Dependabot (Attributed)",
				Categories: fmt.Sprintf("%s!$A$2:$A$%d", sheetName, dataRows+1),
				Values:     fmt.Sprintf("%s!$G$2:$G$%d", sheetName, dataRows+1),
				Fill:       excelize.Fill{Color: []string{"FF6F91"}},
			},
			{
				Name:       "Dependabot (Unattributed)",
				Categories: fmt.Sprintf("%s!$A$2:$A$%d", sheetName, dataRows+1),
				Values:     fmt.Sprintf("%s!$H$2:$H$%d", sheetName, dataRows+1),
				Fill:       excelize.Fill{Color: []string{"C55A5A"}},
			},
		},
		PlotArea: excelize.ChartPlotArea{
			ShowCatName:     false,
			ShowLeaderLines: false,
			ShowPercent:     false,
			ShowSerName:     true,
			ShowVal:         false,
		},
		Dimension: excelize.ChartDimension{
			Width:  640,
			Height: 320,
		},
	})
	
	if err != nil {
		fmt.Printf("Warning: Could not create finding types breakdown chart: %v\n", err)
	}
	
	return nil // Don't fail on chart errors
}

// createAttributionSummary creates a summary table of attribution stats
func (r *Reporter) createAttributionSummary(f *excelize.File, sheetName string, startRow int, results *models.CollectionResults) {
	// Count overall attribution by type
	var (
		codeScanAttr, codeScanUnattr     int
		secretScanAttr, secretScanUnattr int
		dependabotAttr, dependabotUnattr int
	)

	for _, finding := range results.Findings {
		isAttributed := finding.Pod != "No Pod Selected"
		
		switch finding.Type {
		case "code_scanning":
			if isAttributed {
				codeScanAttr++
			} else {
				codeScanUnattr++
			}
		case "secrets":
			if isAttributed {
				secretScanAttr++
			} else {
				secretScanUnattr++
			}
		case "dependabot":
			if isAttributed {
				dependabotAttr++
			} else {
				dependabotUnattr++
			}
		}
	}

	// Summary table headers
	f.SetCellValue(sheetName, fmt.Sprintf("A%d", startRow), "Finding Type")
	f.SetCellValue(sheetName, fmt.Sprintf("B%d", startRow), "Attributed")
	f.SetCellValue(sheetName, fmt.Sprintf("C%d", startRow), "Unattributed")
	f.SetCellValue(sheetName, fmt.Sprintf("D%d", startRow), "Total")
	f.SetCellValue(sheetName, fmt.Sprintf("E%d", startRow), "Attribution %")

	// Summary data
	summaryData := [][]interface{}{
		{"Code Scanning", codeScanAttr, codeScanUnattr, codeScanAttr + codeScanUnattr, 
			calculatePercentage(codeScanAttr, codeScanAttr+codeScanUnattr)},
		{"Secret Scanning", secretScanAttr, secretScanUnattr, secretScanAttr + secretScanUnattr,
			calculatePercentage(secretScanAttr, secretScanAttr+secretScanUnattr)},
		{"Dependabot", dependabotAttr, dependabotUnattr, dependabotAttr + dependabotUnattr,
			calculatePercentage(dependabotAttr, dependabotAttr+dependabotUnattr)},
	}

	for i, data := range summaryData {
		row := startRow + i + 1
		for j, value := range data {
			col := fmt.Sprintf("%c%d", 'A'+j, row)
			f.SetCellValue(sheetName, col, value)
		}
	}

	// Style the summary table
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"E7E6E6"}, Pattern: 1},
	})
	f.SetCellStyle(sheetName, fmt.Sprintf("A%d", startRow), fmt.Sprintf("E%d", startRow), headerStyle)
}

// calculatePercentage calculates percentage with proper handling of zero division
func calculatePercentage(part, total int) string {
	if total == 0 {
		return "0%"
	}
	percentage := float64(part) / float64(total) * 100
	return fmt.Sprintf("%.1f%%", percentage)
}

// createPivotDashboard creates pivot tables and dashboard
func (r *Reporter) createPivotDashboard(f *excelize.File, results *models.CollectionResults) error {
	sheetName := "Dashboard"
	_, err := f.NewSheet(sheetName)
	if err != nil {
		return err
	}

	// Title
	f.SetCellValue(sheetName, "A1", "Security Findings Dashboard")
	titleStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Size: 18},
	})
	f.SetCellStyle(sheetName, "A1", "A1", titleStyle)

	// Quick stats cards
	row := 3
	f.SetCellValue(sheetName, fmt.Sprintf("A%d", row), "Key Metrics")
	headerStyle, _ := f.NewStyle(&excelize.Style{Font: &excelize.Font{Bold: true, Size: 14}})
	f.SetCellStyle(sheetName, fmt.Sprintf("A%d", row), fmt.Sprintf("A%d", row), headerStyle)
	row += 2

	// Create metric cards
	metrics := [][]interface{}{
		{"Total Findings", len(results.Findings)},
		{"High Severity", countBySeverity(results.Findings, "high")},
		{"Medium Severity", countBySeverity(results.Findings, "medium")},
		{"Low Severity", countBySeverity(results.Findings, "low")},
	}

	for i, metric := range metrics {
		col := 'A' + i*3
		f.SetCellValue(sheetName, fmt.Sprintf("%c%d", col, row), metric[0])
		f.SetCellValue(sheetName, fmt.Sprintf("%c%d", col, row+1), metric[1])
		
		// Style the metric cards
		cardStyle, _ := f.NewStyle(&excelize.Style{
			Fill: excelize.Fill{Type: "pattern", Color: []string{"E7E6E6"}, Pattern: 1},
			Border: []excelize.Border{
				{Type: "left", Color: "000000", Style: 1},
				{Type: "top", Color: "000000", Style: 1},
				{Type: "bottom", Color: "000000", Style: 1},
				{Type: "right", Color: "000000", Style: 1},
			},
			Alignment: &excelize.Alignment{Horizontal: "center"},
		})
		f.SetCellStyle(sheetName, fmt.Sprintf("%c%d", col, row), fmt.Sprintf("%c%d", col, row+1), cardStyle)
	}

	return nil
}

// Helper functions
func boolToYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}

func countBySeverity(findings []*models.Finding, severity string) int {
	count := 0
	for _, finding := range findings {
		if finding.Severity == severity {
			count++
		}
	}
	return count
} 