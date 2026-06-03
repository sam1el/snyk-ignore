package cmd

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/sam1el/snyk-ignore/internal/api"
)

var findFilter string
var findAllTypes bool

var findCmd = &cobra.Command{
	Use:   "find [filter]",
	Short: "Find Snyk Code projects",
	Long: `List Snyk Code projects in the organization.

Use --all-types to list every project type (Open Source, Container, etc.).
Optionally filter by project name.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateFlags(true); err != nil {
			return err
		}

		filter := findFilter
		if len(args) > 0 {
			filter = args[0]
		}

		client := api.NewClient(token, orgID)
		if apiBase != "" {
			client.SetBaseURL(apiBase)
		}

		if filter != "" {
			color.Cyan("Fetching projects (filtering: %s)...", filter)
		} else {
			color.Cyan("Fetching projects...")
		}

		allMatching, err := client.ListProjects(filter)
		if err != nil {
			if debug {
				color.Red("Debug - Token: %s", maskSecret(token))
				color.Red("Debug - Org ID: %s", orgID)
				color.Red("Debug - API Base: %s", apiBase)
			}
			return fmt.Errorf("failed to list projects: %w", err)
		}

		if findAllTypes {
			if len(allMatching) == 0 {
				if filter != "" {
					color.Yellow("No projects found matching: %s", filter)
				} else {
					color.Yellow("No projects found")
				}
				return nil
			}
			printProjectTable(cmd, allMatching)
			fmt.Println()
			color.Green("✓ Found %d project(s)", len(allMatching))
			fmt.Println("\nSnyk Code ignores apply to projects with TYPE=sast.")
			return nil
		}

		codeProjects := api.FilterProjectsByType(allMatching, "sast")

		if len(codeProjects) == 0 {
			if filter != "" && len(allMatching) == 0 {
				color.Yellow("No projects found matching: %s", filter)
				return nil
			}
			if filter != "" && len(allMatching) > 0 {
				fmt.Println()
				color.Yellow("No Snyk Code (SAST) projects found matching: %s", filter)
				color.Yellow("Found %d matching project(s) of other types:", len(allMatching))
				printProjectTable(cmd, allMatching)
				fmt.Println()
				color.Yellow("Enable Snyk Code scanning on the repository, then re-run find.")
				return nil
			}
			color.Yellow("No Code projects found")
			return nil
		}

		printProjectTable(cmd, codeProjects)

		fmt.Println()
		color.Green("✓ Found %d Code project(s)", len(codeProjects))
		fmt.Println("\nTo ignore findings, use:")
		color.Cyan("  snyk-ignore ignore --project <PROJECT_ID> --severity low")

		return nil
	},
}

func printProjectTable(cmd *cobra.Command, projects []api.Project) {
	w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "PROJECT_ID\tPROJECT_NAME\tTYPE\tORG_ID")
	fmt.Fprintln(w, strings.Repeat("-", 36)+"\t"+strings.Repeat("-", 50)+"\t"+strings.Repeat("-", 12)+"\t"+strings.Repeat("-", 36))

	for _, proj := range projects {
		name := proj.Attrs.Name
		if len(name) > 48 {
			name = name[:48]
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", proj.ID, name, proj.Attrs.Type, proj.Rels.Organization.Data.ID)
	}
	w.Flush()
}

var findOrgsCmd = &cobra.Command{
	Use:   "orgs",
	Short: "List Snyk organizations",
	Long: `List all Snyk organizations you have access to.

Shows both the slug (used in Web UI) and UUID (used in API).`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateFlags(false); err != nil {
			return err
		}

		client := api.NewClient(token, "")
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
		fmt.Fprintln(w, strings.Repeat("-", 30)+"\t"+strings.Repeat("-", 30)+"\t"+strings.Repeat("-", 36))

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
	findCmd.Flags().StringVarP(&findFilter, "filter", "f", "", "Filter projects by name (substring match)")
	findCmd.Flags().BoolVar(&findAllTypes, "all-types", false, "List all project types, not just Snyk Code (sast)")
	rootCmd.AddCommand(findOrgsCmd)
}
