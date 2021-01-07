package handlers

/**
 * Panther is a Cloud-Native SIEM for the Modern Security Team.
 * Copyright (C) 2020 Panther Labs Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

import (
	"net/http"
	"strings"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/expression"
	"go.uber.org/zap"

	"github.com/panther-labs/panther/api/lambda/analysis/models"
	"github.com/panther-labs/panther/pkg/gatewayapi"
)

func (API) ListPacks(input *models.ListPacksInput) *events.APIGatewayProxyResponse {
	// Standardize input
	input.NameContains = strings.ToLower(input.NameContains)
	if input.Page == 0 {
		input.Page = defaultPage
	}
	if input.PageSize == 0 {
		input.PageSize = defaultPageSize
	}
	//if input.SortBy == "" {
	//	input.SortBy = "id"
	//}
	//if input.SortDir == "" {
	//	input.SortDir = defaultSortDir
	//}

	// Scan dynamo
	scanInput, err := packScanInput(input)
	if err != nil {
		return &events.APIGatewayProxyResponse{
			Body: err.Error(), StatusCode: http.StatusInternalServerError}
	}

	var items []packTableItem
	err = scanPackPages(scanInput, func(item packTableItem) error {
		items = append(items, item)
		return nil
	})
	if err != nil {
		zap.L().Error("failed to scan packs", zap.Error(err))
		return &events.APIGatewayProxyResponse{StatusCode: http.StatusInternalServerError}
	}

	// Sort and page
	// TODO: no sorting logic implemented yet... I wanted to re-use the logic that was already there, but couldn't
	// think of a good way to do it because the sorting funcs take in a detection table item (vs a
	// pack table entry)
	// Here are a few options I thought of, but didn't like any of them:
	// wrap the sort functions so they could take pack entry OR detection entry?
	// wrap the packItem / tableItem in a higher level struct to use in each func, check which one is non-null?
	// - is there a better way?
	//sortItems(items, "id", input.SortDir, nil)

	var paging models.Paging
	paging, items = pagePackItems(items, input.Page, input.PageSize)

	// Convert to output struct
	result := models.ListPacksOutput{
		Packs:  make([]models.Pack, 0, len(items)),
		Paging: paging,
	}
	for _, item := range items {
		result.Packs = append(result.Packs, *item.Pack())
	}

	return gatewayapi.MarshalResponse(&result, http.StatusOK)
}

func packScanInput(input *models.ListPacksInput) (*dynamodb.ScanInput, error) {
	var filters []expression.ConditionBuilder

	if input.CreatedBy != "" {
		filters = append(filters, expression.Equal(expression.Name("createdBy"),
			expression.Value(input.CreatedBy)))
	}

	if input.Enabled != nil {
		filters = append(filters, expression.Equal(
			expression.Name("enabled"), expression.Value(*input.Enabled)))
	}

	if input.EnabledRelease != "" {
		filters = append(filters, expression.Equal(expression.Name("enabledRelease"),
			expression.Value(input.EnabledRelease)))
	}

	if input.LastModifiedBy != "" {
		filters = append(filters, expression.Equal(expression.Name("lastModifiedBy"),
			expression.Value(input.LastModifiedBy)))
	}

	if input.Managed != nil {
		filters = append(filters, expression.Equal(expression.Name("managed"), expression.Value(*input.Managed)))
	}

	if input.NameContains != "" {
		filters = append(filters, expression.Contains(expression.Name("lowerId"), input.NameContains).
			Or(expression.Contains(expression.Name("lowerDisplayName"), input.NameContains)))
	}

	if input.Source != "" {
		filters = append(filters, expression.Contains(expression.Name("source"), input.Source))
	}

	if input.UpdateAvailable != nil {
		filters = append(filters, expression.Equal(expression.Name("updateAvailable"), expression.Value(*input.UpdateAvailable)))
	}

	if len(input.AvailableReleases) > 0 {
		// a data model with no resource types applies to all of them
		releaseFilter := expression.AttributeNotExists(expression.Name("availableReleases"))
		for _, releaseTag := range input.AvailableReleases {
			releaseFilter = releaseFilter.Or(expression.Contains(expression.Name("availableReleases"), releaseTag))
		}
		filters = append(filters, releaseFilter)
	}

	return buildScanInput(models.TypePack, []string{}, filters...)
}

// Truncate list of items to the requested page
func pagePackItems(items []packTableItem, page, pageSize int) (models.Paging, []packTableItem) {
	if len(items) == 0 {
		return models.Paging{}, nil
	}

	totalPages := len(items) / pageSize
	if len(items)%pageSize > 0 {
		totalPages++ // Add one more to page count if there is an incomplete page at the end
	}

	paging := models.Paging{
		ThisPage:   page,
		TotalItems: len(items),
		TotalPages: totalPages,
	}

	// Truncate to just the requested page
	lowerBound := intMin((page-1)*pageSize, len(items))
	upperBound := intMin(page*pageSize, len(items))
	return paging, items[lowerBound:upperBound]
}
