package reporting

import (
	"encoding/csv"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/xuri/excelize/v2"
	"github.com/sirupsen/logrus"

	"github-findings-manager/internal/models"
)

// ExcelReporter generates Excel reports with dashboards
type ExcelReporter struct {
	outputPath string
	logger     *logrus.Logger
}

// NewExcelReporter creates a new Excel reporter
func NewExcelReporter(outputPath string) *ExcelReporter {
	return &ExcelReporter{
		outputPath: outputPath,
		logger:     logrus.New(),
	}
}

// GenerateReport creates a comprehensive Excel report
func (r *ExcelReporter) GenerateReport(findings []*models.Finding) error {
	f := excelize.NewFile()
	defer f.Close()

	// Create summary and analysis
	summary := models.SummarizeFindings(findings)
	quarters := models.GroupFindingsByQuarter(findings)

	// Generate sheets
	if err := r.createSummarySheet(f, summary, findings); err != nil {
		return fmt.Errorf("failed to create summary sheet: %w", err)
	}

	if err := r.createQuarterlySheets(f, quarters); err != nil {
		return fmt.Errorf("failed to create quarterly sheets: %w", err)
	}

	if err := r.createDetailedFindingsSheet(f, findings); err != nil {
		return fmt.Errorf("failed to create detailed findings sheet: %w", err)
	}

	if err := r.createRepositorySheet(f, summary); err != nil {
		return fmt.Errorf("failed to create repository sheet: %w", err)
	}

	if err := r.createDashboardSheet(f, summary); err != nil {
		return fmt.Errorf("failed to create dashboard sheet: %w", err)
	}

	// Delete default sheet
	f.DeleteSheet("Sheet1")

	// Save the file
	if err := f.SaveAs(r.outputPath); err != nil {
		return fmt.Errorf("failed to save Excel file: %w", err)
	}

	r.logger.WithField("path", r.outputPath).Info("Excel report generated successfully")
	return nil
}

// createSummarySheet creates the main summary sheet
func (r *ExcelReporter) createSummarySheet(f *excelize.File, summary *models.FindingsSummary, findings []*models.Finding) error {
	sheetName := "Summary"
	index, err := f.NewSheet(sheetName)
	if err != nil {
		return err
	}
	f.SetActiveSheet(index)

	// Set up styles
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Size: 12, Color: "FFFFFF"},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"4472C4"}, Pattern: 1},
		Border: []excelize.Border{
			{Type: "left", Color: "000000", Style: 1},
			{Type: "top", Color: "000000", Style: 1},
			{Type: "bottom", Color: "000000", Style: 1},
			{Type: "right", Color: "000000", Style: 1},
		},
	})

	dataStyle, _ := f.NewStyle(&excelize.Style{
		Border: []excelize.Border{
			{Type: "left", Color: "000000", Style: 1},
			{Type: "top", Color: "000000", Style: 1},
			{Type: "bottom", Color: "000000", Style: 1},
			{Type: "right", Color: "000000", Style: 1},
		},
	})

	// Title
	f.SetCellValue(sheetName, "A1", "GitHub Security Findings Summary")
	titleStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Size: 16},
	})
	f.SetCellStyle(sheetName, "A1", "A1", titleStyle)
	f.SetCellValue(sheetName, "A2", fmt.Sprintf("Generated: %s", summary.GeneratedAt.Format("2006-01-02 15:04:05")))

	// Overview section
	row := 4
	f.SetCellValue(sheetName, "A"+strconv.Itoa(row), "Overview")
	f.SetCellStyle(sheetName, "A"+strconv.Itoa(row), "A"+strconv.Itoa(row), headerStyle)
	row++

	f.SetCellValue(sheetName, "A"+strconv.Itoa(row), "Total Findings")
	f.SetCellValue(sheetName, "B"+strconv.Itoa(row), summary.TotalFindings)
	f.SetCellStyle(sheetName, "A"+strconv.Itoa(row), "B"+strconv.Itoa(row), dataStyle)
	row++

	f.SetCellValue(sheetName, "A"+strconv.Itoa(row), "Total Repositories")
	f.SetCellValue(sheetName, "B"+strconv.Itoa(row), len(summary.Repositories))
	f.SetCellStyle(sheetName, "A"+strconv.Itoa(row), "B"+strconv.Itoa(row), dataStyle)
	row += 2

	// Findings by Type
	f.SetCellValue(sheetName, "A"+strconv.Itoa(row), "Findings by Type")
	f.SetCellStyle(sheetName, "A"+strconv.Itoa(row), "A"+strconv.Itoa(row), headerStyle)
	row++

	for findingType, count := range summary.ByType {
		f.SetCellValue(sheetName, "A"+strconv.Itoa(row), string(findingType))
		f.SetCellValue(sheetName, "B"+strconv.Itoa(row), count)
		f.SetCellStyle(sheetName, "A"+strconv.Itoa(row), "B"+strconv.Itoa(row), dataStyle)
		row++
	}
	row++

	// Findings by Severity
	f.SetCellValue(sheetName, "A"+strconv.Itoa(row), "Findings by Severity")
	f.SetCellStyle(sheetName, "A"+strconv.Itoa(row), "A"+strconv.Itoa(row), headerStyle)
	row++

	for severity, count := range summary.BySeverity {
		f.SetCellValue(sheetName, "A"+strconv.Itoa(row), string(severity))
		f.SetCellValue(sheetName, "B"+strconv.Itoa(row), count)
		f.SetCellStyle(sheetName, "A"+strconv.Itoa(row), "B"+strconv.Itoa(row), dataStyle)
		row++
	}
	row++

	// Ownership Distribution by Finding Type
	f.SetCellValue(sheetName, "A"+strconv.Itoa(row), "Ownership Distribution by Finding Type")
	f.SetCellStyle(sheetName, "A"+strconv.Itoa(row), "A"+strconv.Itoa(row), headerStyle)
	row++

	// Create detailed ownership breakdown
	if err := r.createOwnershipBreakdown(f, sheetName, findings, &row, headerStyle, dataStyle); err != nil {
		r.logger.WithError(err).Warn("Failed to create ownership breakdown")
	}

	// New Findings by Quarter
	f.SetCellValue(sheetName, "A"+strconv.Itoa(row), "New Findings by Quarter")
	f.SetCellStyle(sheetName, "A"+strconv.Itoa(row), "A"+strconv.Itoa(row), headerStyle)
	row++

	// Create quarterly metrics table
	if err := r.createQuarterlyMetrics(f, sheetName, findings, &row, headerStyle, dataStyle); err != nil {
		r.logger.WithError(err).Warn("Failed to create quarterly metrics")
	}

	// Add charts
	if err := r.createSummaryCharts(f, sheetName, summary); err != nil {
		r.logger.WithError(err).Warn("Failed to create summary charts")
	}

	// Fix AutoFilter calls
	if err := f.AutoFilter(sheetName, fmt.Sprintf("A1:R%d", len(findings)+1), []excelize.AutoFilterOptions{}); err != nil {
		return fmt.Errorf("failed to set auto filter: %w", err)
	}

	return nil
}

// createOwnershipBreakdown creates a breakdown by finding type and ownership
func (r *ExcelReporter) createOwnershipBreakdown(f *excelize.File, sheetName string, findings []*models.Finding, row *int, headerStyle, dataStyle int) error {
	// Group findings by type and ownership
	stats := make(map[string]map[string]int)
	
	r.logger.WithField("total_findings", len(findings)).Info("Creating ownership breakdown")
	
	for _, finding := range findings {
		findingType := string(finding.Type)
		ownership := finding.GetOwnership()
		
		r.logger.WithFields(map[string]interface{}{
			"finding_type": findingType,
			"ownership":    ownership,
			"repo":         finding.Repository,
		}).Debug("Processing finding for ownership breakdown")
		
		if stats[findingType] == nil {
			stats[findingType] = make(map[string]int)
		}
		stats[findingType][ownership]++
	}
	
	r.logger.WithField("stats", stats).Info("Ownership statistics computed")
	
	// Calculate totals for each type and ownership
	codeqlOwned := 0
	codeqlUnowned := 0
	secretsOwned := 0
	secretsUnowned := 0
	dependabotOwned := 0
	dependabotUnowned := 0
	
	if codeqlStats, ok := stats["code_scanning"]; ok {
		codeqlOwned = codeqlStats["Owned"]
		codeqlUnowned = codeqlStats["Unowned"]
	}
	if secretsStats, ok := stats["secrets"]; ok {
		secretsOwned = secretsStats["Owned"]
		secretsUnowned = secretsStats["Unowned"]
	}
	if dependabotStats, ok := stats["dependabot"]; ok {
		dependabotOwned = dependabotStats["Owned"]
		dependabotUnowned = dependabotStats["Unowned"]
	}
	
	// Create the breakdown table
	breakdownData := []struct {
		Label string
		Count int
	}{
		{"CodeQL - Owned", codeqlOwned},
		{"CodeQL - Unowned", codeqlUnowned},
		{"Secrets - Owned", secretsOwned},
		{"Secrets - Unowned", secretsUnowned},
		{"Dependabot - Owned", dependabotOwned},
		{"Dependabot - Unowned", dependabotUnowned},
	}
	
	for _, item := range breakdownData {
		f.SetCellValue(sheetName, "A"+strconv.Itoa(*row), item.Label)
		f.SetCellValue(sheetName, "B"+strconv.Itoa(*row), item.Count)
		f.SetCellStyle(sheetName, "A"+strconv.Itoa(*row), "B"+strconv.Itoa(*row), dataStyle)
		*row++
	}
	
	// Add totals
	*row++
	f.SetCellValue(sheetName, "A"+strconv.Itoa(*row), "Total Owned")
	f.SetCellValue(sheetName, "B"+strconv.Itoa(*row), codeqlOwned+secretsOwned+dependabotOwned)
	f.SetCellStyle(sheetName, "A"+strconv.Itoa(*row), "B"+strconv.Itoa(*row), headerStyle)
	*row++
	
	f.SetCellValue(sheetName, "A"+strconv.Itoa(*row), "Total Unowned")
	f.SetCellValue(sheetName, "B"+strconv.Itoa(*row), codeqlUnowned+secretsUnowned+dependabotUnowned)
	f.SetCellStyle(sheetName, "A"+strconv.Itoa(*row), "B"+strconv.Itoa(*row), headerStyle)
	*row++
	
	*row++ // Add spacing after the table
	
	return nil
}

// createQuarterlyMetrics creates a quarterly breakdown by type and ownership
func (r *ExcelReporter) createQuarterlyMetrics(f *excelize.File, sheetName string, findings []*models.Finding, row *int, headerStyle, dataStyle int) error {
	// Group findings by quarter
	quarterStats := make(map[string]map[string]map[string]int)
	
	for _, finding := range findings {
		quarter := finding.GetQuarter()
		findingType := string(finding.Type)
		ownership := finding.GetOwnership()
		
		if quarterStats[quarter] == nil {
			quarterStats[quarter] = make(map[string]map[string]int)
		}
		if quarterStats[quarter][findingType] == nil {
			quarterStats[quarter][findingType] = make(map[string]int)
		}
		quarterStats[quarter][findingType][ownership]++
	}
	
	// Sort quarters
	var quarters []string
	for quarter := range quarterStats {
		quarters = append(quarters, quarter)
	}
	sort.Strings(quarters)
	
	// Create headers
	headers := []string{"Quarter", "CodeQL-Owned", "CodeQL-Unowned", "Secrets-Owned", "Secrets-Unowned", "Dependabot-Owned", "Dependabot-Unowned", "Total"}
	for i, header := range headers {
		cell := fmt.Sprintf("%c%d", 'A'+i, *row)
		f.SetCellValue(sheetName, cell, header)
		f.SetCellStyle(sheetName, cell, cell, headerStyle)
	}
	*row++
	
	// Add data for each quarter
	for _, quarter := range quarters {
		stats := quarterStats[quarter]
		
		// Calculate totals for each type and ownership
		codeqlOwned := 0
		codeqlUnowned := 0
		secretsOwned := 0
		secretsUnowned := 0
		dependabotOwned := 0
		dependabotUnowned := 0
		
		if codeqlStats, ok := stats["code_scanning"]; ok {
			codeqlOwned = codeqlStats["Owned"]
			codeqlUnowned = codeqlStats["Unowned"]
		}
		if secretsStats, ok := stats["secrets"]; ok {
			secretsOwned = secretsStats["Owned"]
			secretsUnowned = secretsStats["Unowned"]
		}
		if dependabotStats, ok := stats["dependabot"]; ok {
			dependabotOwned = dependabotStats["Owned"]
			dependabotUnowned = dependabotStats["Unowned"]
		}
		
		total := codeqlOwned + codeqlUnowned + secretsOwned + secretsUnowned + dependabotOwned + dependabotUnowned
		
		// Add row data
		rowData := []interface{}{
			quarter,
			codeqlOwned,
			codeqlUnowned,
			secretsOwned,
			secretsUnowned,
			dependabotOwned,
			dependabotUnowned,
			total,
		}
		
		for i, value := range rowData {
			cell := fmt.Sprintf("%c%d", 'A'+i, *row)
			f.SetCellValue(sheetName, cell, value)
			f.SetCellStyle(sheetName, cell, cell, dataStyle)
		}
		*row++
	}
	
	// Set column widths
	f.SetColWidth(sheetName, "A", "A", 12)
	f.SetColWidth(sheetName, "B", "H", 15)
	
	*row++ // Add spacing after the table
	
	return nil
}

// createQuarterlySheets creates sheets for each quarter
func (r *ExcelReporter) createQuarterlySheets(f *excelize.File, quarters map[string]*models.QuarterlyFindings) error {
	// Sort quarters
	var quarterNames []string
	for quarter := range quarters {
		quarterNames = append(quarterNames, quarter)
	}
	sort.Strings(quarterNames)

	for _, quarterName := range quarterNames {
		quarterly := quarters[quarterName]
		sheetName := fmt.Sprintf("Q-%s", quarterName)
		
		// Sanitize sheet name
		sheetName = strings.ReplaceAll(sheetName, "/", "-")
		if len(sheetName) > 31 {
			sheetName = sheetName[:31]
		}

		_, err := f.NewSheet(sheetName)
		if err != nil {
			continue
		}

		if err := r.createQuarterlySheet(f, sheetName, quarterly); err != nil {
			r.logger.WithError(err).WithField("quarter", quarterName).Error("Failed to create quarterly sheet")
		}
	}

	return nil
}

// createQuarterlySheet creates a single quarterly sheet
func (r *ExcelReporter) createQuarterlySheet(f *excelize.File, sheetName string, quarterly *models.QuarterlyFindings) error {
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Size: 12, Color: "FFFFFF"},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"4472C4"}, Pattern: 1},
	})

	// Title
	f.SetCellValue(sheetName, "A1", fmt.Sprintf("Findings for %s", quarterly.Quarter))
	titleStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Size: 14},
	})
	f.SetCellStyle(sheetName, "A1", "A1", titleStyle)

	// Summary
	row := 3
	f.SetCellValue(sheetName, "A"+strconv.Itoa(row), "Total Findings")
	f.SetCellValue(sheetName, "B"+strconv.Itoa(row), quarterly.Summary.Total)
	row += 2

	// Headers for findings table
	headers := []string{"Repository", "Type", "Severity", "State", "Title", "Created", "Age (Days)", "URL"}
	for i, header := range headers {
		cell := fmt.Sprintf("%c%d", 'A'+i, row)
		f.SetCellValue(sheetName, cell, header)
		f.SetCellStyle(sheetName, cell, cell, headerStyle)
	}
	row++

	// Add findings data
	for _, finding := range quarterly.Findings {
		repoName := "Unknown"
		if finding.Repository != nil {
			repoName = finding.Repository.FullName
		}

		f.SetCellValue(sheetName, "A"+strconv.Itoa(row), repoName)
		f.SetCellValue(sheetName, "B"+strconv.Itoa(row), string(finding.Type))
		f.SetCellValue(sheetName, "C"+strconv.Itoa(row), string(finding.Severity))
		f.SetCellValue(sheetName, "D"+strconv.Itoa(row), string(finding.State))
		f.SetCellValue(sheetName, "E"+strconv.Itoa(row), finding.Title)
		f.SetCellValue(sheetName, "F"+strconv.Itoa(row), finding.CreatedAt.Format("2006-01-02"))
		f.SetCellValue(sheetName, "G"+strconv.Itoa(row), finding.GetAgeInDays())
		
		// Add hyperlink
		if finding.HTMLURL != "" {
			f.SetCellHyperLink(sheetName, "H"+strconv.Itoa(row), finding.HTMLURL, "External")
			f.SetCellValue(sheetName, "H"+strconv.Itoa(row), "View on GitHub")
		}
		
		row++
	}

	// Set column widths
	f.SetColWidth(sheetName, "A", "A", 30)
	f.SetColWidth(sheetName, "B", "B", 15)
	f.SetColWidth(sheetName, "C", "C", 10)
	f.SetColWidth(sheetName, "D", "D", 10)
	f.SetColWidth(sheetName, "E", "E", 50)
	f.SetColWidth(sheetName, "F", "F", 12)
	f.SetColWidth(sheetName, "G", "G", 12)
	f.SetColWidth(sheetName, "H", "H", 20)

	return nil
}

// createDetailedFindingsSheet creates a detailed findings sheet
func (r *ExcelReporter) createDetailedFindingsSheet(f *excelize.File, findings []*models.Finding) error {
	sheetName := "All Findings"
	_, err := f.NewSheet(sheetName)
	if err != nil {
		return err
	}

	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Size: 11, Color: "FFFFFF"},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"4472C4"}, Pattern: 1},
	})

	// Headers
	headers := []string{
		"ID", "Repository", "Owner", "Pod", "Type", "Severity", "State", 
		"Title", "Description", "Rule Name", "Tool", "Location", 
		"Created", "Updated", "Age (Days)", "Quarter", "Ownership", "URL",
	}

	for i, header := range headers {
		cell := fmt.Sprintf("%c1", 'A'+i)
		if i > 25 {
			cell = fmt.Sprintf("A%c1", 'A'+(i-26))
		}
		f.SetCellValue(sheetName, cell, header)
		f.SetCellStyle(sheetName, cell, cell, headerStyle)
	}

	// Add data
	for i, finding := range findings {
		row := i + 2
		repoName := "Unknown"
		owner := "Unknown"
		pod := "Unknown"
		if finding.Repository != nil {
			repoName = finding.Repository.FullName
			owner = finding.Repository.Owner
			pod = finding.Repository.Pod
		}

		data := []interface{}{
			finding.ID,
			repoName,
			owner,
			pod,
			string(finding.Type),
			string(finding.Severity),
			string(finding.State),
			finding.Title,
			finding.Description,
			finding.RuleName,
			finding.Tool,
			finding.Location,
			finding.CreatedAt.Format("2006-01-02 15:04:05"),
			finding.UpdatedAt.Format("2006-01-02 15:04:05"),
			finding.GetAgeInDays(),
			finding.GetQuarter(),
			finding.GetOwnership(),
			finding.HTMLURL,
		}

		for j, value := range data {
			cell := fmt.Sprintf("%c%d", 'A'+j, row)
			if j > 25 {
				cell = fmt.Sprintf("A%c%d", 'A'+(j-26), row)
			}
			f.SetCellValue(sheetName, cell, value)
			
			// Add hyperlink for URL column
			if j == len(data)-1 && finding.HTMLURL != "" {
				f.SetCellHyperLink(sheetName, cell, finding.HTMLURL, "External")
			}
		}
	}

	// Set column widths
	widths := []float64{15, 30, 15, 15, 15, 10, 10, 40, 60, 20, 15, 30, 20, 20, 10, 10, 10, 20}
	for i, width := range widths {
		col := fmt.Sprintf("%c", 'A'+i)
		if i > 25 {
			col = fmt.Sprintf("A%c", 'A'+(i-26))
		}
		f.SetColWidth(sheetName, col, col, width)
	}

	// Fix AutoFilter calls
	if err := f.AutoFilter(sheetName, fmt.Sprintf("A1:R%d", len(findings)+1), []excelize.AutoFilterOptions{}); err != nil {
		return fmt.Errorf("failed to set auto filter: %w", err)
	}

	return nil
}

// createRepositorySheet creates a repository summary sheet
func (r *ExcelReporter) createRepositorySheet(f *excelize.File, summary *models.FindingsSummary) error {
	sheetName := "Repositories"
	_, err := f.NewSheet(sheetName)
	if err != nil {
		return err
	}

	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Size: 11, Color: "FFFFFF"},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"4472C4"}, Pattern: 1},
	})

	// Headers
	headers := []string{
		"Repository", "Owner", "Pod", "Environment", "Total Findings", 
		"Critical", "High", "Medium", "Low", "Code Scanning", "Secrets", "Dependabot", "URL",
	}

	for i, header := range headers {
		cell := fmt.Sprintf("%c1", 'A'+i)
		f.SetCellValue(sheetName, cell, header)
		f.SetCellStyle(sheetName, cell, cell, headerStyle)
	}

	// Add repository data
	row := 2
	for _, repoSummary := range summary.Repositories {
		repo := repoSummary.Repository
		
		f.SetCellValue(sheetName, "A"+strconv.Itoa(row), repo.FullName)
		f.SetCellValue(sheetName, "B"+strconv.Itoa(row), repo.Owner)
		f.SetCellValue(sheetName, "C"+strconv.Itoa(row), repo.Pod)
		f.SetCellValue(sheetName, "D"+strconv.Itoa(row), repo.EnvironmentType)
		f.SetCellValue(sheetName, "E"+strconv.Itoa(row), repoSummary.FindingCount)
		f.SetCellValue(sheetName, "F"+strconv.Itoa(row), repoSummary.BySeverity[models.SeverityCritical])
		f.SetCellValue(sheetName, "G"+strconv.Itoa(row), repoSummary.BySeverity[models.SeverityHigh])
		f.SetCellValue(sheetName, "H"+strconv.Itoa(row), repoSummary.BySeverity[models.SeverityMedium])
		f.SetCellValue(sheetName, "I"+strconv.Itoa(row), repoSummary.BySeverity[models.SeverityLow])
		f.SetCellValue(sheetName, "J"+strconv.Itoa(row), repoSummary.ByType[models.FindingTypeCodeQL])
		f.SetCellValue(sheetName, "K"+strconv.Itoa(row), repoSummary.ByType[models.FindingTypeSecrets])
		f.SetCellValue(sheetName, "L"+strconv.Itoa(row), repoSummary.ByType[models.FindingTypeDependabot])
		
		// Add hyperlink
		if repo.URL != "" {
			f.SetCellHyperLink(sheetName, "M"+strconv.Itoa(row), repo.URL, "External")
			f.SetCellValue(sheetName, "M"+strconv.Itoa(row), "View on GitHub")
		}
		
		row++
	}

	// Set column widths
	widths := []float64{35, 20, 15, 15, 15, 10, 10, 10, 10, 15, 10, 15, 20}
	for i, width := range widths {
		col := fmt.Sprintf("%c", 'A'+i)
		f.SetColWidth(sheetName, col, col, width)
	}

	// Fix AutoFilter calls
	if err := f.AutoFilter(sheetName, fmt.Sprintf("A1:M%d", row-1), []excelize.AutoFilterOptions{}); err != nil {
		return fmt.Errorf("failed to set auto filter: %w", err)
	}

	return nil
}

// createDashboardSheet creates an interactive dashboard
func (r *ExcelReporter) createDashboardSheet(f *excelize.File, summary *models.FindingsSummary) error {
	sheetName := "Dashboard"
	index, err := f.NewSheet(sheetName)
	if err != nil {
		return err
	}
	f.SetActiveSheet(index)

	// Title
	f.SetCellValue(sheetName, "B2", "GitHub Security Findings Dashboard")
	titleStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Size: 18},
	})
	f.SetCellStyle(sheetName, "B2", "B2", titleStyle)

	// Key metrics
	f.SetCellValue(sheetName, "B4", "Key Metrics")
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Size: 14},
	})
	f.SetCellStyle(sheetName, "B4", "B4", headerStyle)

	metricStyle, _ := f.NewStyle(&excelize.Style{
		Font: &excelize.Font{Bold: true, Size: 24},
		Fill: excelize.Fill{Type: "pattern", Color: []string{"E7E6E6"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center", Vertical: "center"},
	})

	// Total findings
	f.SetCellValue(sheetName, "B6", "Total Findings")
	f.SetCellValue(sheetName, "B7", summary.TotalFindings)
	f.SetCellStyle(sheetName, "B7", "B7", metricStyle)

	// Critical + High severity
	criticalHigh := summary.BySeverity[models.SeverityCritical] + summary.BySeverity[models.SeverityHigh]
	f.SetCellValue(sheetName, "D6", "Critical/High")
	f.SetCellValue(sheetName, "D7", criticalHigh)
	f.SetCellStyle(sheetName, "D7", "D7", metricStyle)

	// Owned vs Unowned
	owned := summary.ByOwnership["Owned"]
	unowned := summary.ByOwnership["Unowned"]
	f.SetCellValue(sheetName, "F6", "Owned Repos")
	f.SetCellValue(sheetName, "F7", owned)
	f.SetCellStyle(sheetName, "F7", "F7", metricStyle)

	f.SetCellValue(sheetName, "H6", "Unowned Repos")
	f.SetCellValue(sheetName, "H7", unowned)
	f.SetCellStyle(sheetName, "H7", "H7", metricStyle)

	// Add charts and visualizations
	if err := r.createDashboardCharts(f, sheetName, summary); err != nil {
		r.logger.WithError(err).Warn("Failed to create dashboard charts")
	}

	return nil
}

// createSummaryCharts creates charts for the summary sheet
func (r *ExcelReporter) createSummaryCharts(f *excelize.File, sheetName string, summary *models.FindingsSummary) error {
	// Create chart data for finding types
	f.SetCellValue(sheetName, "D4", "Type")
	f.SetCellValue(sheetName, "E4", "Count")
	row := 5
	for findingType, count := range summary.ByType {
		f.SetCellValue(sheetName, "D"+strconv.Itoa(row), string(findingType))
		f.SetCellValue(sheetName, "E"+strconv.Itoa(row), count)
		row++
	}

	// Create pie chart
	chart := &excelize.Chart{
		Type: excelize.Pie,
		Series: []excelize.ChartSeries{
			{
				Name:       "Findings by Type",
				Categories: "=Summary!$B$2:$B$5",
				Values:     "=Summary!$C$2:$C$5",
			},
		},
		PlotArea: excelize.ChartPlotArea{
			ShowPercent: true,
		},
	}

	if err := f.AddChart(sheetName, "G4", chart); err != nil {
		return err
	}

	return nil
}

// createDashboardCharts creates charts for the dashboard
func (r *ExcelReporter) createDashboardCharts(f *excelize.File, sheetName string, summary *models.FindingsSummary) error {
	// Create bar chart for findings by severity
	err := f.AddChart(sheetName, "B15", &excelize.Chart{
		Type: excelize.Bar,
		Series: []excelize.ChartSeries{
			{
				Name:       "Findings by Severity",
				Categories: "=Summary!$E$2:$E$5",
				Values:     "=Summary!$F$2:$F$5",
			},
		},
	})

	// Create line chart for findings trend
	err = f.AddChart(sheetName, "D15", &excelize.Chart{
		Type: excelize.Line,
		Series: []excelize.ChartSeries{
			{
				Name:       "Findings Trend",
				Categories: "=Quarterly!$A$2:$A$5",
				Values:     "=Quarterly!$B$2:$B$5",
			},
		},
	})

	return err
}

// GenerateCSV generates a CSV version of the findings
func (r *ExcelReporter) GenerateCSV(findings []*models.Finding, csvPath string) error {
	file, err := os.Create(csvPath)
	if err != nil {
		return fmt.Errorf("failed to create CSV file: %w", err)
	}
	defer file.Close()

	writer := csv.NewWriter(file)
	defer writer.Flush()

	// Write header
	headers := []string{
		"ID", "Repository", "Owner", "Pod", "Type", "Severity", "State",
		"Title", "Description", "Rule Name", "Tool", "Location",
		"Created", "Updated", "Age (Days)", "Quarter", "Ownership", "URL",
	}
	writer.Write(headers)

	// Write data
	for _, finding := range findings {
		repoName := "Unknown"
		owner := "Unknown"
		pod := "Unknown"
		if finding.Repository != nil {
			repoName = finding.Repository.FullName
			owner = finding.Repository.Owner
			pod = finding.Repository.Pod
		}

		record := []string{
			finding.ID,
			repoName,
			owner,
			pod,
			string(finding.Type),
			string(finding.Severity),
			string(finding.State),
			finding.Title,
			finding.Description,
			finding.RuleName,
			finding.Tool,
			finding.Location,
			finding.CreatedAt.Format("2006-01-02 15:04:05"),
			finding.UpdatedAt.Format("2006-01-02 15:04:05"),
			strconv.Itoa(finding.GetAgeInDays()),
			finding.GetQuarter(),
			finding.GetOwnership(),
			finding.HTMLURL,
		}

		writer.Write(record)
	}

	r.logger.WithField("path", csvPath).Info("CSV report generated successfully")
	return nil
}