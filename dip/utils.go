package dip

import (
	"context"
	"errors"
	"fmt"
	"github.com/fuxi-inc/dip-common-lib/sdk/dis"
	idl2 "github.com/fuxi-inc/dip-common-lib/sdk/dis/idl"
	"github.com/fuxi-inc/dip-common-lib/utils/converter"
	"github.com/gin-gonic/gin"
	"github.com/pydio/cells/v4/common/log"
	"github.com/pydio/cells/v4/common/runtime"
	"go.uber.org/zap"
)

func GetPublicKey(ctx context.Context, duDoi string) (string, error) {
	disHost := runtime.DipDisHost()
	disQHost := runtime.DipDisQHost()
	disClient := dis.NewClient().InitLogger(zap.NewExample()).InitDis(disHost).InitDisQ(disQHost)
	search := make([]idl2.SearchType, 1)
	search[0] = idl2.PubKey

	req := &idl2.ApiDOQueryRequest{Doi: duDoi, Type: search, DirectQuery: false}
	resp, err := disClient.ApiDOQuery(&gin.Context{}, req)
	if err != nil {
		log.Logger(ctx).Error("GetData getPublicKey ApiDOQuery error", zap.Error(err))
		return "", err
	}

	if resp == nil || resp.Data == nil {
		log.Logger(ctx).Error("GetData getPublicKey ApiDOQuery response is nil")
		return "", errors.New("ApiDOQuery return nil error")
	}

	if !resp.Errno.IsSuccess() {
		log.Logger(ctx).Error(fmt.Sprintf("GetData getPublicKey ApiDOQuery response is not Success: %s", converter.ToString(resp)))
		return "", fmt.Errorf("GetData getPublicKey ApiDOQuery response is not Success: %s", converter.ToString(resp))
	}
	return resp.Data.PubKey, nil
}

func GetDW(ctx context.Context, duDoi string) (string, error) {
	disHost := runtime.DipDisHost()
	disQHost := runtime.DipDisQHost()
	disClient := dis.NewClient().InitLogger(zap.NewExample()).InitDis(disHost).InitDisQ(disQHost)
	search := make([]idl2.SearchType, 1)
	search[0] = idl2.Owner

	req := &idl2.ApiDOQueryRequest{Doi: duDoi, Type: search, DirectQuery: false}
	resp, err := disClient.ApiDOQuery(&gin.Context{}, req)
	if err != nil {
		log.Logger(ctx).Error("GetData GetDW ApiDOQuery error", zap.Error(err))
		return "", err
	}

	if resp == nil || resp.Data == nil {
		log.Logger(ctx).Error("GetData GetDW ApiDOQuery response is nil")
		return "", errors.New("ApiDOQuery return nil error")
	}

	if !resp.Errno.IsSuccess() {
		log.Logger(ctx).Error(fmt.Sprintf("GetData GetDW ApiDOQuery response is not Success: %s", converter.ToString(resp)))
		return "", fmt.Errorf("GetData GetDW ApiDOQuery response is not Success: %s", converter.ToString(resp))
	}
	return resp.Data.Owner, nil
}
