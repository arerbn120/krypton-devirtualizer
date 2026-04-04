using System;
using System.Collections.Generic;
using System.Linq;
using Krypton.Core;
using Krypton.Core.Payload;
using Krypton.Core.Parser;

namespace Krypton.Pipeline.Stages
{
    public class ResourceParsing : IStage
    {
        public string Name => nameof(ResourceParsing);

        public void Run(DevirtualizationCtx Ctx)
        {
            var resourceData = ReadResourceData(Ctx);
            if (resourceData == null)
                throw new DevirtualizationException("Could not parse any VM resource payload.");

            Ctx.ResourceData = resourceData;
            Ctx.Parser = resourceData.LegacyParser;
            Ctx.PayloadBlob = resourceData.PayloadBlob;
            Ctx.PayloadLayout = ResolvePayloadLayout(Ctx, resourceData);
            Ctx.OperandModel = ResolveOperandModel(Ctx, resourceData, Ctx.PayloadLayout);

            Ctx.Options.Logger.Success("Successfully Parsed Resource!");
            Ctx.Options.Logger.InfoStr("Strings Read", Ctx.PayloadLayout?.Strings?.Count.ToString() ?? "0");
            Ctx.Options.Logger.InfoStr("MethodKeys Read", Ctx.PayloadLayout?.MethodCount.ToString() ?? "0");
            Ctx.Options.Logger.InfoStr("Operands Read", Ctx.GetOperandTypes().Length.ToString());
        }

        private VmResourceData ReadResourceData(DevirtualizationCtx ctx)
        {
            var readers = new List<IResourceReader>();
            if (ctx.ResourceReaders != null)
                readers.AddRange(ctx.ResourceReaders.Where(r => r != null));
            if (ctx.ResourceReader != null && readers.All(r => !ReferenceEquals(r, ctx.ResourceReader)))
                readers.Add(ctx.ResourceReader);
            if (readers.Count == 0)
                readers.Add(new ResourceParser());

            DevirtualizationException lastFailure = null;
            foreach (var reader in readers)
            {
                try
                {
                    var data = reader.Parse(ctx);
                    if (data != null)
                        return data;
                }
                catch (DevirtualizationException ex)
                {
                    lastFailure = ex;
                    ctx.Options.Logger.Warning($"Resource reader {reader.GetType().Name} failed: {ex.Message}");
                }
            }

            throw lastFailure ?? new DevirtualizationException("All configured resource readers failed.");
        }

        private VmPayloadLayout ResolvePayloadLayout(DevirtualizationCtx ctx, VmResourceData resourceData)
        {
            if (resourceData?.PayloadLayout != null && resourceData.PayloadLayout.MethodCount > 0)
                return resourceData.PayloadLayout;

            var parserChain = BuildPayloadParserChain(ctx);
            foreach (var parser in parserChain)
            {
                try
                {
                    var layout = parser.Parse(resourceData.PayloadBlob, resourceData.LegacyParser);
                    if (layout != null && layout.MethodCount > 0)
                        return layout;
                }
                catch (Exception ex)
                {
                    ctx.Options.Logger.Warning(
                        $"Payload parser {parser.GetType().Name} failed: {ex.Message}");
                }
            }

            throw new DevirtualizationException("No payload parser produced a valid VM layout.");
        }

        private OperandModel ResolveOperandModel(
            DevirtualizationCtx ctx,
            VmResourceData resourceData,
            VmPayloadLayout payloadLayout)
        {
            if (resourceData?.OperandModel != null && resourceData.OperandModel.Count > 0)
                return resourceData.OperandModel;

            var extractors = new List<IOperandModelExtractor>();
            if (ctx.OperandModelExtractors != null)
                extractors.AddRange(ctx.OperandModelExtractors.Where(e => e != null));
            if (extractors.Count == 0)
                extractors.Add(new OperandModelExtractor());

            foreach (var extractor in extractors)
            {
                try
                {
                    var model = extractor.Extract(payloadLayout);
                    if (model != null && model.Count > 0)
                        return model;
                }
                catch (Exception ex)
                {
                    ctx.Options.Logger.Warning(
                        $"Operand extractor {extractor.GetType().Name} failed: {ex.Message}");
                }
            }

            return new OperandModel(Array.Empty<OperandDescriptor>());
        }

        private IList<IVmPayloadParser> BuildPayloadParserChain(DevirtualizationCtx ctx)
        {
            var chain = new List<IVmPayloadParser>();
            if (ctx.PayloadParsers != null)
                chain.AddRange(ctx.PayloadParsers.Where(p => p != null));

            if (chain.Count == 0)
                chain.Add(new LegacyVmPayloadParser());

            return chain;
        }
    }
}
