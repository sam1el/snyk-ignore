package cmd

import (
	"fmt"
	"text/tabwriter"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/sam1el/snyk-ignore/internal/api"
)

var reverseCmd = &cobra.Command{
	Use:   "reverse",
	Short: "Reverse/undo ignore policies",
	Long: `List and delete ignore policies that were created for bulk ignoring.

This allows you to undo bulk ignore operations by removing the policies.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := validateFlags(true); err != nil {
			return err
		}

		client := api.NewClient(token, orgID)
		if apiBase != "" {
			client.SetBaseURL(apiBase)
		}

		color.Cyan("Fetching ignore policies...")
		policies, err := client.ListPolicies()
		if err != nil {
			return fmt.Errorf("failed to list policies: %w", err)
		}

		if len(policies) == 0 {
			color.Yellow("No ignore policies found")
			return nil
		}

		// Filter to policies we created (names starting with "Ignore-")
		var relevantPolicies []api.Policy
		for _, p := range policies {
			if len(p.Attrs.Name) >= 7 && p.Attrs.Name[:7] == "Ignore-" {
				relevantPolicies = append(relevantPolicies, p)
			}
		}

		if len(relevantPolicies) == 0 {
			color.Yellow("No bulk-ignore policies found (looking for policies named 'Ignore-*')")
			return nil
		}

		// Show policies
		w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
		fmt.Fprintln(w, "POLICY_ID\tNAME\tCREATED_AT")
		fmt.Fprintln(w, "---\t---\t---")

		for _, p := range relevantPolicies {
			fmt.Fprintf(w, "%s\t%s\t%s\n", p.ID, p.Attrs.Name, p.Attrs.CreatedAt)
		}
		w.Flush()

		fmt.Println()
		color.Yellow("⚠️  To DELETE these %d policies, use:", len(relevantPolicies))
		color.Cyan("  snyk-ignore reverse --delete")

		if deleteFlag {
			fmt.Println()
			color.Red("Deleting %d policies...", len(relevantPolicies))

			deleted := 0
			failed := 0

			for i, p := range relevantPolicies {
				fmt.Printf("[%d/%d] Deleting %s...", i+1, len(relevantPolicies), p.Attrs.Name)
				err := client.DeletePolicy(p.ID)
				if err != nil {
					color.Red(" FAILED: %v", err)
					failed++
				} else {
					color.Green(" OK")
					deleted++
				}
			}

			fmt.Println()
			fmt.Println("=== Summary ===")
			color.Green("Policies deleted: %d", deleted)
			if failed > 0 {
				color.Red("Policies failed: %d", failed)
			}

			if failed > 0 {
				return fmt.Errorf("%d policies could not be deleted", failed)
			}

			color.Green("✓ All policies deleted successfully!")
		}

		return nil
	},
}

var deleteFlag bool

func init() {
	reverseCmd.Flags().BoolVar(&deleteFlag, "delete", false, "Actually delete the policies (without this flag, only shows what would be deleted)")
	rootCmd.AddCommand(reverseCmd)
}
