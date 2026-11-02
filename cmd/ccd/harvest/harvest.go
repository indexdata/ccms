package harvest

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/indexdata/ccms/cmd/ccd/dbx"
	"github.com/indexdata/ccms/cmd/ccd/log"
	"github.com/indexdata/ccms/cmd/ccd/marcxml"
	"github.com/jackc/pgx/v5"
	"github.com/nassibnassar/goharvest/oai"
)

func Harvest(connString string) {
	for {
		harvestLoop(connString)
		log.Info("harvesting: paused")
		time.Sleep(1 * time.Hour)
		log.Info("harvesting: restarted")
	}
}

func harvestLoop(connString string) {
	defer func() {
		if r := recover(); r != nil {
			logError(r)
		}
	}()

	ctx := context.TODO()
	conn, err := dbx.Connect(ctx, connString)
	if err != nil {
		logError(err)
		return
	}
	defer conn.Close(ctx)

	/*
		(&oai.Request{
			BaseURL: "http://services.kb.nl/mdo/oai", Set: "DTS", MetadataPrefix: "dcx",
			From: "2012-09-06T014:00:00.000Z",
		}).HarvestRecords(func(record *oai.Record) {
			fmt.Printf("%s\n\n", record.Metadata.Body[0:500])
		})
	*/

	// HarvestIdentifier(connString, "b6c6160c-6bbb-41cc-9e07-690049d7d537")
	// HarvestIdentifier(connString, "002c3ae5-3cf5-47c3-8bd5-87c57cdab8f1")

	// The following OAI-PMH verbs are supported by the Reservoir: ListIdentifiers, ListRecords,
	// GetRecord, Identify.
	rq := &oai.Request{
		BaseURL: "https://cclp-okapi.reshare-dev.indexdata.com/_/invoke/tenant/cclp/reservoir/oai",

		Verb: "ListRecords",
		// From:  "2026-02-01T22:52:14Z",
		// Until: "2026-09-01T22:52:16Z",
		// From:  "2025-11-14T05:45:03Z",
		// Until: "2030-01-01T01:01:01Z",

		//Verb:           "GetRecord",
		//Identifier:     "b6c6160c-6bbb-41cc-9e07-690049d7d537",
		//MetadataPrefix: "marcxml",
	}
	//fmt.Printf("%#v\n\n", rq)
	//fmt.Println("harvesting...")
	//var c int
	rq.HarvestRecords(func(record *oai.Record) {
		//rq.Harvest(func(rs *oai.Response) {
		//fmt.Printf("identifier: %s\n", record.Header.Identifier)
		//fmt.Printf("datestamp: %s\n", record.Header.DateStamp)
		//fmt.Printf("setspec: %v\n", record.Header.SetSpec)
		//fmt.Printf("status: %s\n", record.Header.Status)
		//fmt.Printf("about: %s\n", record.About.Body)
		//fmt.Printf("metadata: %s\n", record.Metadata.Body)

		//fmt.Printf("%s %s\n", record.Header.Identifier, record.Header.DateStamp)

		/*
			fmt.Printf("=======================================================================\n")
			fmt.Printf("%v\n", c)
			c++
			fmt.Printf("=======================================================================\n")
			fmt.Printf("%#v\n", rs)
			fmt.Printf("=======================================================================\n")
			fmt.Printf("retrieved = %s\n", rs.ResponseDate)
			fmt.Printf("identifier = %s\n", rs.GetRecord.Record.Header.Identifier)
			fmt.Printf("data = %s\n", rs.GetRecord.Record.Metadata.Body)
		*/
		// fmt.Printf("%#v\n", record.Metadata)
		// fmt.Printf("%q\n", record.Metadata.Body)
		m, err := marcxml.Unmarshal(record.Metadata.Body)
		//m, err := marcxml.Unmarshal(rs.GetRecord.Record.Metadata.Body)
		if err != nil {
			// fmt.Printf("----\n%s\n----\n", string(record.Metadata.Body))
			logError("unmarshalling: " + err.Error())
			return
		}
		metadata := strings.TrimSpace(string(record.Metadata.Body))
		identifier := strings.TrimPrefix(record.Header.Identifier, "oai:")
		dateStamp := record.Header.DateStamp
		author100a := m.Lookup("100", "", "", "a")
		author := nilIfEmpty(&author100a)
		title245 := m.Lookup("245", "", "", "a")
		title245b := m.Lookup("245", "", "", "b")
		if title245b != "" {
			title245 = title245 + "\n" + title245b
		}
		//title245 := strings.Join([]string{title245a, title245b}, "\n")
		title := nilIfEmpty(&title245)
		fullVendorName := m.Lookup("999", "1", "3", "a")
		availability := m.Lookup("999", "1", "3", "z")
		//placePub := m.Lookup("260", "a")

		libraryCount := m.LookupLibraryCount()
		libraryHoldingsCount := m.LookupLibraryHoldingsCount()
		onlineDatabaseHoldingsCount := m.LookupOnlineDatabaseHoldingsCount()
		vendorHoldingsCount := m.LookupVendorHoldingsCount()
		holdingsCount := m.LookupHoldingsCount()

		_ = m
		//c++
		//if c%10000 == 0 {
		//        log.Info("harvested %d records", c)
		//}

		// placeOfPublication := nilIfEmpty(&placePub)

		// temporarily skip records with no author to give us better example data
		// if author == nil {
		// 	return
		// }

		tx, err := conn.Begin(ctx)
		if err != nil {
			logError("starting transaction" + err.Error())
			return
		}
		defer tx.Rollback(ctx)

		var id int64
		q := "insert into ccms.md (identifier, retrieved, date_stamp, data) " +
			"values ($1, $2, $3, $4) on conflict do nothing returning id"
		err = tx.QueryRow(ctx, q, identifier, time.Now(), dateStamp, metadata).Scan(&id)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			//log.Info("conflict: skipping record %s", identifier)
		case err != nil:
			logError("writing to table md: " + err.Error())
			return
		default:
		}

		if id != 0 {
			q = "insert into ccms.attr (id, author, title, full_vendor_name, availability, library_count, library_holdings_count, online_database_holdings_count, vendor_holdings_count, holdings_count) " +
				"values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) on conflict do nothing"
			if _, err = tx.Exec(ctx, q, id, author, title, fullVendorName, availability, libraryCount, libraryHoldingsCount, onlineDatabaseHoldingsCount, vendorHoldingsCount, holdingsCount); err != nil {
				logError("writing to table attr: " + err.Error())
				return
			}

			q = "insert into ccms.reserve (id) " +
				"values ($1) on conflict do nothing"
			if _, err = tx.Exec(ctx, q, id); err != nil {
				logError("writing to table reserve: " + err.Error())
				return
			}

			//log.Info("(%d) %s %s / %s", id, identifier, author100a, title245)
		}

		if err = tx.Commit(ctx); err != nil {
			logError("committing transaction: " + err.Error())
			return
		}
	})
	// TODO add to ccd.conf:
	// [oai]
	// base_url = https://cclp-okapi.reshare-dev.indexdata.com/_/invoke/tenant/cclp/reservoir/oai
	fmt.Printf("=======================================================================\n")
	fmt.Printf("harvest exiting\n")
	fmt.Printf("=======================================================================\n")
}

func HarvestIdentifier(connString string, identifier string) {
	(&oai.Request{
		BaseURL: "https://cclp-okapi.reshare-dev.indexdata.com/_/invoke/tenant/cclp/reservoir/oai",

		//Verb:  "ListRecords",
		//From:  "2025-10-14T22:52:14Z",
		//Until: "2025-10-14T22:52:16Z",

		Verb:           "GetRecord",
		Identifier:     identifier,
		MetadataPrefix: "marcxml",
	}).HarvestRecords(func(record *oai.Record) {
		//fmt.Printf("identifier: %s\n", record.Header.Identifier)
		//fmt.Printf("datestamp: %s\n", record.Header.DateStamp)
		//fmt.Printf("setspec: %v\n", record.Header.SetSpec)
		//fmt.Printf("status: %s\n", record.Header.Status)
		//fmt.Printf("about: %s\n", record.About.Body)
		//fmt.Printf("metadata: %s\n", record.Metadata.Body)

		fmt.Printf("%s %s\n", record.Header.Identifier, record.Header.DateStamp)
	})
}

func nilIfEmpty(s *string) *string {
	if *s == "" {
		return nil
	}
	return s
}

func logError(e any) {
	log.Error("ERROR:  harvesting: %v", e)
}
