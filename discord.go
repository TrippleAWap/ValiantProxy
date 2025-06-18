package main

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"fmt"
	"github.com/bwmarrin/discordgo"
	"github.com/joho/godotenv"
	"io"
	"net/http"
	"os"
	"time"
)

var (
	adMessage = "ValiantProxy | discord.gg/Sz3kzqFc68"
	color     = 0xAA00EE
	webhook   discordgo.Webhook
	bot       *discordgo.Session
)

//go:embed cat.jpg
var image []byte

func sendMessage(message string) error {
	if bot == nil {
		return nil
	}
	_, err := bot.WebhookExecute(webhook.ID, webhook.Token, true, &discordgo.WebhookParams{
		Embeds: []*discordgo.MessageEmbed{
			{
				Thumbnail: &discordgo.MessageEmbedThumbnail{
					URL: "attachment://image.jpg",
				},
				Timestamp:   time.Now().Format(time.RFC3339),
				Title:       "ValiantProxy",
				Description: message,
				Color:       color,
				Footer: &discordgo.MessageEmbedFooter{
					Text: adMessage,
				},
			},
		},
		Files: []*discordgo.File{
			{
				Name:        "image.jpg",
				ContentType: "image/jpeg",
				Reader:      bytes.NewReader(image),
			},
		},
	})
	return err
}

func init() {
	_ = godotenv.Load()
	webhookUrl := os.Getenv("WEBHOOK_URL")
	if webhookUrl == "" {
		fmt.Printf("IGNORING DISCORD OPTIONS: WEBHOOK_URL not set\n")
		return
	}
	data, err := http.Get(webhookUrl)
	if err != nil {
		panic(err)
	}
	defer data.Body.Close()
	bytesV, err := io.ReadAll(data.Body)
	if err != nil {
		panic(err)
	}
	if err := json.Unmarshal(bytesV, &webhook); err != nil {
		panic(err)
	}
	fmt.Printf("Fetched Webhook\n\tID: %s\tChannel ID: %s\tToken: %s\n", webhook.ID, webhook.ChannelID, webhook.Token)
	webhook.User = &discordgo.User{
		Username:    "ValiantProxy",
		Verified:    true,
		PublicFlags: discordgo.UserFlagBugHunterLevel1 | discordgo.UserFlagBugHunterLevel2 | discordgo.UserFlagSystem | discordgo.UserFlagDiscordPartner,
	}
	bot, err = discordgo.New("Bot " + webhook.Token)
	if err != nil {
		panic(err)
	}
}

func checkError(err error) bool {
	if err != nil {
		_ = sendMessage(fmt.Sprintf("**ValiantProxy encountered an error:**\n```\n%v\n```", err))
		fmt.Println(err)
	}
	return err != nil
}
