package cmd

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/sam1el/snyk-ignore/internal/api"
)

var findCmd = &cobra.Command{
	Use:   "find [filter]",
	Short: "Find Snyk Code projects",
	Long: `List all Snyk Code projects in the organization.

Optionally filter by project name.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateFlags(); err != nil {
			return err
		}

		filter := ""
		if len(args) > 0 {
			filter = args[0]
		}

		client := api.NewClient(token, orgID)
		if apiBase != "" {
			client.SetBaseURL(apiBase)
		}

		if filter != "" {
			color.Cyan("Fetching Snyk Code projects (filtering: %s)...", filter)
		} else {
			color.Cyan("Fetching Snyk Code projects...")
		}
		projects, err := client.ListCodeProjects(filter)
		if err != nil {
			if debug {
				color.Red("Debug - Token: %s", maskSecret(token))
				color.Red("Debug - Org ID: %s", orgID)
				color.Red("Debug - API Base: %s", apiBase)
			}
			return fmt.Errorf("failed to list projects: %w", err)
		}

		if len(projects) == 0 {
			if filter != "" {
				color.Yellow("No Code projects found matching: %s", filter)
			} else {
				color.Yellow("No Code projects found")
			}
			return nil
		}

		// Check if we got non-code projects (debug info)
		codeCount := 0
		for _, proj := range projects {
			if proj.Attrs.Type == "sast" {
				codeCount++
			}
		}

		if codeCount == 0 && len(projects) > 0 {
			color.Yellow("Found %d project(s) but none are SAST/Code type:", len(projects))
			for i, proj := range projects {
				if i >= 5 { // Show first 5
					color.Yellow("  ... and %d more", len(projects)-5)
					break
				}
				color.Yellow("  • %s (type: %s)", proj.Attrs.Name, proj.Attrs.Type)
			}
			return nil
		}

		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "PROJECT_ID\tPROJECT_NAME\tTYPE\tORG_ID")
		fmt.Fprintln(w, strings.Repeat("-", 36) + "\t" + strings.Repeat("-", 50) + "\t" + strings.Repeat("-", 12) + "\t" + strings.Repeat("-", 36))

		for _, proj := range projects {
			name := proj.Attrs.Name
			if len(name) > 48 {
				name = name[:48]
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", proj.ID, name, proj.Attrs.Type, proj.Rels.Organization.Data.ID)
		}
		w.Flush()

		fmt.Println()
		color.Green("✓ Found %d Code project(s)", codeCount)
		fmt.Println("\nTo ignore findings, use:")
		color.Cyan("  snyk-ignore ignore --project <PROJECT_ID> --severity low")

		return nil
	},
}

var findOrgsCmd = &cobra.Command{
	Use:   "orgs",
	Short: "List Snyk organizations",
	Long: `List all Snyk organizations you have access to.

Shows both the slug (used in Web UI) and UUID (used in API).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateFlags(); err != nil {
			return err
		}

		client := api.NewClient(token, orgID)
		if apiBase != "" {
			client.SetBaseURL(apiBase)
		}

		color.Cyan("Fetching Snyk organizations...")
		orgs, err := client.ListOrganizations()
		if err != nil {
			return fmt.Errorf("failed to list orgs: %w", err)
		}

		if len(orgs) == 0 {
			color.Yellow("No organizations found")
			return nil
		}

		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "ORG_NAME\tORG_SLUG\tORG_UUID")
		fmt.Fprintln(w, strings.Repeat("-", 30) + "\t" + strings.Repeat("-", 30) + "\t" + strings.Repeat("-", 36))

		for _, org := range orgs {
			fmt.Fprintf(w, "%s\t%s\t%s\n", org.Attrs.Name, org.Attrs.Slug, org.ID)
		}
		w.Flush()

		fmt.Println()
		color.Green("✓ Found %d organization(s)", len(orgs))
		fmt.Println("\nFor API calls, use the ORG_UUID (not the slug)")
		fmt.Println("Set it with:")
		color.Cyan("  snyk-ignore config set --token YOUR_TOKEN --org-id <ORG_UUID>")

		return nil
	},
}

func init() {
	findCmd.Flags().StringP("filter", "f", "", "Filter projects by name (substring match)")
	rootCmd.AddCommand(findOrgsCmd)
}
