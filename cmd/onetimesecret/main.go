// Command onetimesecret manages secret sent through onetimesecret.com
//
//		Create and send secrets to friends
//
//		Usage:
//		onetimesecret [command]
//
//		Available Commands:
//		create      create a secret
//		help        Help about any command
//		inspect     View metadata about a secret
//
//		Flags:
//			--apitoken string   API token for onetimesecret
//			--cfg string        configuration file
//			--username string   Username for onetimesecret
//		-v, --verbose           More verbose output
//
//		Use "onetimesecret [command] --help" for more information about a command.
//
// The default path for the configuration file is ~/.onetimesecret.yaml and the schema is:
//
//      username: <username>
//      apitoken: <apitoken>
//
// To get an API token simply signup at https://onetimesecret.com/
package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"github.com/stengaard/onetimesecret"
)

func main() {
	cmd := cobra.Command{
		Use:   "onetimesecret",
		Short: "Create and send secrets to friends",

		PersistentPreRunE: func(ctx *cobra.Command, args []string) error {
			return nil
		},
	}

	cmd.PersistentFlags().String("cfg", "", "configuration file")
	cmd.PersistentFlags().BoolP("verbose", "v", false, "More verbose output")
	cmd.PersistentFlags().String("username", "", "Username for onetimesecret")
	cmd.PersistentFlags().String("apitoken", "", "API token for onetimesecret")
	cmd.AddCommand(
		handleCreate(),
		handleInspect(),
	)

	cobra.OnInitialize(func() {

		viper.SetConfigName(".onetimesecret")
		viper.AddConfigPath("$HOME")
		cfgFile, _ := cmd.Flags().GetString("cfg")
		if cfgFile != "" {
			viper.SetConfigFile(cfgFile)
		}

		viper.BindEnv("username", "OTS_USERNAME")
		viper.BindEnv("apitoken", "OTS_APITOKEN")

		viper.AutomaticEnv()
		err := viper.ReadInConfig()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error reading configuration: %v\n", err)
			os.Exit(-1)
		}
	})

	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v", err)
		os.Exit(1)
	}

}

func getClient(cmd *cobra.Command) onetimesecret.Client {
	f := cmd.Flags()
	username, _ := f.GetString("username")
	apitoken, _ := f.GetString("apitoken")

	if username == "" {
		username = viper.GetString("username")
	}
	if apitoken == "" {
		apitoken = viper.GetString("apitoken")
	}
	client := onetimesecret.Client{}
	if apitoken != "" && username != "" {
		client.APIToken = apitoken
		client.Username = username
	}
	return client
}

func handleCreate() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "create",
		Short: "create a secret",
		RunE: func(cmd *cobra.Command, args []string) error {
			f := cmd.Flags()
			var (
				value, _ = f.GetString("value")
				email, _ = f.GetString("email")

				m   onetimesecret.Metadata
				err error
			)

			c := getClient(cmd)

			opts := []onetimesecret.Option{}
			if email != "" {
				opts = append(opts, onetimesecret.WithRecipient(email))
			}

			if value != "" {
				m, err = c.CreateSecret(value, opts...)
				if err != nil {
					return fmt.Errorf("could not create secret: %v", err)
				}
			} else {
				s, err := c.GenerateSecret(opts...)
				if err != nil {
					return fmt.Errorf("could not generate secret: %v", err)
				}

				fmt.Println("Secret value:", s.Value)
				m = s.Metadata
			}

			if email != "" {
				fmt.Printf("Email with link has been sent to %v\n", m.Recipient)
			} else {
				fmt.Println("Secret path: ", "https://onetimesecret.com/secret/"+m.SecretKey)
			}
			fmt.Println("Metadata key (do not share):", m.MetadataKey)

			return nil
		},
	}

	f := cmd.Flags()
	f.String("value", "", "Send a secret with this value")
	f.String("email", "", "Send a link this email")

	return cmd
}

func handleInspect() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect",
		Short: "View metadata about a secret",
		RunE: func(cmd *cobra.Command, args []string) error {
			c := getClient(cmd)
			for i := range args {
				m, err := c.RetrieveMetadata(args[i])
				if err != nil {
					return fmt.Errorf("cannot fetch info about secret: %v", err)
				}

				fmt.Println("Password set:", m.PassphraseRequired)
				fmt.Println("Status      :", m.Status())
				if m.Status() == "read" {
					fmt.Println("Received at :", m.Received.Time())
				}
				fmt.Println("Expires     :", m.Deadline())
				fmt.Println("Created on  :", m.Created.Time())
				fmt.Println("Created by  :", m.CustomerID)
				if len(m.Recipient) > 0 {
					fmt.Println("Sent to     :", m.Recipient[0])
				}
				if m.SecretKey != "" {
					fmt.Println("Secret URL  :", "https://onetimesecret.com/secret/"+m.SecretKey)
				}

			}
			return nil
		},
	}
	return cmd
}
